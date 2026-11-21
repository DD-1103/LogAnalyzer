using System.Text;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Helpers;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Controllers;

public class AlertsController(AppDbContext db, UserManager<AppUser> userManager, IAuditLog audit, ILogger<AlertsController> logger) : Controller
{
    private const int PageSize = 25;
    private const int MaxEvidenceShown = 200;

    [HttpGet]
    public async Task<IActionResult> Index(AlertStatus? status, Severity? severity, AttackType? attackType,
        string? ip, int? logFileId, bool escalated = false, int page = 1)
    {
        // Mark alerts as "seen" for the nav badge, but remember the previous visit to highlight new rows.
        var userId = userManager.GetUserId(User);
        var previousSeenAt = await db.Users.Where(u => u.Id == userId).Select(u => u.AlertsSeenAt).FirstOrDefaultAsync();
        await db.Users.Where(u => u.Id == userId)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.AlertsSeenAt, DateTime.UtcNow));

        var query = Filter(status, severity, attackType, ip, logFileId, escalated);

        var count = await query.CountAsync();
        var totalPages = Math.Max(1, (int)Math.Ceiling(count / (double)PageSize));
        page = Math.Clamp(page, 1, totalPages);

        // Severity is stored as text, so sort by an explicit rank (Critical first).
        var alerts = await Sort(query)
            .Skip((page - 1) * PageSize)
            .Take(PageSize)
            .ToListAsync();

        return View(new AlertListViewModel
        {
            Alerts = alerts,
            Status = status,
            Severity = severity,
            AttackType = attackType,
            Ip = ip,
            LogFileId = logFileId,
            Escalated = escalated,
            Page = page,
            TotalPages = totalPages,
            TotalCount = count,
            PreviousSeenAt = previousSeenAt
        });
    }

    [HttpGet]
    public async Task<IActionResult> Details(long id, [FromServices] ThreatIntelService threatIntel)
    {
        var alert = await db.Alerts.AsNoTracking()
            .Include(a => a.Rule)
            .Include(a => a.LogFile)
            .Include(a => a.AssignedTo)
            .FirstOrDefaultAsync(a => a.Id == id);
        if (alert is null)
            return NotFound();

        var evidence = await db.AlertEvidence.AsNoTracking()
            .Where(e => e.AlertId == id)
            .Select(e => e.LogEvent!)
            .OrderBy(e => e.Timestamp).ThenBy(e => e.LineNumber)
            .Take(MaxEvidenceShown)
            .ToListAsync();

        var me = await userManager.GetUserAsync(User);
        var isAdmin = User.IsInRole(Roles.Admin);
        return View(new AlertDetailsViewModel
        {
            Alert = alert,
            AllowedStatuses = SocPermissions.AllowedStatuses(isAdmin, me?.Tier, alert, me?.Id),
            CanEscalate = SocPermissions.CanEscalate(isAdmin, me?.Tier, alert),
            CanClaim = SocPermissions.CanClaim(isAdmin, me?.Tier, alert),
            CanRelease = SocPermissions.CanRelease(isAdmin, alert, me?.Id),
            CanGiveVerdict = SocPermissions.CanGiveVerdict(isAdmin, me?.Tier, alert, me?.Id),
            IsOwner = SocPermissions.IsOwner(alert, me?.Id),
            Comments = await db.AlertComments.AsNoTracking().Where(c => c.AlertId == id)
                .OrderBy(c => c.CreatedAt).ThenBy(c => c.Id).ToListAsync(),
            Tier = SocPermissions.EffectiveTier(isAdmin, me?.Tier),
            Evidence = evidence,
            EvidenceShown = evidence.Count,
            IpInfo = await db.IpInfos.AsNoTracking().FirstOrDefaultAsync(i => i.Ip == alert.SourceIp),
            Providers = threatIntel.Providers,
            Reputation = (await threatIntel.GetCachedAsync(alert.SourceIp)).ToDictionary(r => r.Provider)
        });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Update(long id, AlertUpdateModel model)
    {
        var alert = await db.Alerts.FirstOrDefaultAsync(a => a.Id == id);
        if (alert is null)
            return NotFound();

        if (!ModelState.IsValid)
        {
            TempData["Error"] = string.Join(" ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).Distinct());
            return RedirectToAction(nameof(Details), new { id });
        }

        // SOC 1 works on open alerts only; closing, false positives and reopening are SOC 2 / admin decisions.
        // The tier is read from the database, so a change by an administrator applies at once.
        var me = await userManager.GetUserAsync(User);
        if (!SocPermissions.CanUpdate(User.IsInRole(Roles.Admin), me?.Tier, alert, me?.Id, model.Status))
        {
            await audit.WriteAsync("Alert.Update.Denied", $"#{id} {alert.Title}", $"{alert.Status} -> {model.Status}");
            TempData["Error"] = SocPermissions.IsEscalated(alert)
                ? alert.AssignedToId is null
                    ? "This alert is escalated to SOC 2. A SOC 2 analyst has to take it first."
                    : "This escalated alert belongs to another SOC 2 analyst. Add a comment with your opinion instead."
                : SocPermissions.IsOpen(alert.Status)
                    ? $"SOC 1 analysts cannot set an alert to {model.Status}. Escalate it to SOC 2 instead."
                    : "This alert is closed. Only SOC 2 analysts or administrators can reopen or change it.";
            return RedirectToAction(nameof(Details), new { id });
        }

        var oldStatus = alert.Status;
        alert.Status = model.Status;
        alert.Notes = string.IsNullOrWhiteSpace(model.Notes) ? null : model.Notes.Trim();

        // The analyst who picks the alert up becomes its owner.
        if (model.Status == AlertStatus.Investigating && alert.AssignedToId is null)
            alert.AssignedToId = userManager.GetUserId(User);

        await db.SaveChangesAsync();
        await audit.WriteAsync("Alert.Update", $"#{id} {alert.Title}", $"{oldStatus} -> {model.Status}");
        logger.LogInformation("User {User} changed alert {Id} from {Old} to {New}",
            User.Identity?.Name, id, oldStatus, model.Status);

        TempData["Success"] = "Alert updated.";
        return RedirectToAction(nameof(Details), new { id });
    }

    /// <summary>SOC 1 hands an open alert over to SOC 2: it is marked escalated, unassigned and stays open.</summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Escalate(long id, string? reason, [FromServices] NotificationService notifications)
    {
        var alert = await db.Alerts.FirstOrDefaultAsync(a => a.Id == id);
        if (alert is null)
            return NotFound();
        var me = await userManager.GetUserAsync(User);
        if (!SocPermissions.CanEscalate(User.IsInRole(Roles.Admin), me?.Tier, alert))
        {
            TempData["Error"] = "This alert cannot be escalated (already escalated, closed, or you are not SOC 1).";
            return RedirectToAction(nameof(Details), new { id });
        }

        var cleanReason = string.IsNullOrWhiteSpace(reason) ? null : Cut(AuditLog.Clean(reason.Trim())!, 500);
        alert.EscalatedAt = DateTime.UtcNow;
        alert.EscalatedBy = User.Identity?.Name;
        alert.EscalatedById = me?.Id;
        alert.EscalationReason = cleanReason;
        alert.Status = AlertStatus.Investigating;
        alert.AssignedToId = null; // a SOC 2 analyst takes it from the hub
        alert.ClaimedAt = null;
        alert.Verdict = null;
        AddEvent(alert.Id, me, "escalation", cleanReason is null ? "Escalated to SOC 2." : $"Escalated to SOC 2: {cleanReason}");
        await db.SaveChangesAsync();

        var notified = await notifications.NotifySoc2Async(alert, me?.Id, NotificationService.DisplayName(me, User.Identity?.Name));
        await audit.WriteAsync("Alert.Escalate", $"#{id} {alert.Title}", cleanReason);
        logger.LogInformation("User {User} escalated alert {Id} to SOC 2", User.Identity?.Name, id);
        TempData["Success"] = notified > 0
            ? $"Alert escalated to SOC 2. {notified} SOC 2 analyst(s) were notified."
            : "Alert escalated to SOC 2.";
        return RedirectToAction(nameof(Details), new { id });
    }

    /// <summary>A SOC 2 analyst takes an escalation: they become its owner, everyone sees their name on it.</summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Claim(long id, string? returnUrl, [FromServices] NotificationService notifications)
    {
        var me = await userManager.GetUserAsync(User);
        var alert = await db.Alerts.FirstOrDefaultAsync(a => a.Id == id);
        if (alert is null || me is null)
            return NotFound();
        if (!SocPermissions.CanClaim(User.IsInRole(Roles.Admin), me.Tier, alert))
        {
            TempData["Error"] = alert.AssignedToId is null
                ? "Only SOC 2 analysts can take escalated alerts."
                : "Another SOC 2 analyst has already taken this alert.";
            return BackTo(returnUrl, id);
        }

        // Atomic: only one of two analysts pressing "Take it" at the same time wins.
        var won = await db.Alerts
            .Where(a => a.Id == id && a.AssignedToId == null && a.EscalatedAt != null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(a => a.AssignedToId, me.Id)
                .SetProperty(a => a.ClaimedAt, DateTime.UtcNow)
                .SetProperty(a => a.Status, a => a.Status == AlertStatus.New ? AlertStatus.Investigating : a.Status));
        if (won == 0)
        {
            TempData["Error"] = "Another SOC 2 analyst took this alert a moment ago.";
            return BackTo(returnUrl, id);
        }

        var name = NotificationService.DisplayName(me);
        AddEvent(id, me, "claim", $"{name} took the escalation.");
        await db.SaveChangesAsync();
        await notifications.NotifyUserAsync(alert.EscalatedById, me.Id, "claim",
            $"{name} took your escalated alert #{id}", alert.Title, NotificationService.AlertLink(id));
        await audit.WriteAsync("Alert.Claim", $"#{id} {alert.Title}");
        TempData["Success"] = "You own this escalation now. Give a verdict when you have analysed it.";
        return BackTo(returnUrl, id);
    }

    /// <summary>The owner (or an administrator) gives the escalation back to the SOC 2 queue.</summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Release(long id, string? returnUrl)
    {
        var me = await userManager.GetUserAsync(User);
        var alert = await db.Alerts.Include(a => a.AssignedTo).FirstOrDefaultAsync(a => a.Id == id);
        if (alert is null || me is null)
            return NotFound();
        if (!SocPermissions.CanRelease(User.IsInRole(Roles.Admin), alert, me.Id))
        {
            TempData["Error"] = "Only the owner or an administrator can give this escalation back.";
            return BackTo(returnUrl, id);
        }

        var previous = NotificationService.DisplayName(alert.AssignedTo, "the previous owner");
        alert.AssignedToId = null;
        alert.ClaimedAt = null;
        AddEvent(id, me, "release", SocPermissions.IsOwner(alert, me.Id) || alert.AssignedTo?.Id == me.Id
            ? $"{NotificationService.DisplayName(me)} gave the escalation back to the queue."
            : $"{NotificationService.DisplayName(me)} released the escalation from {previous}.");
        await db.SaveChangesAsync();
        await audit.WriteAsync("Alert.Release", $"#{id} {alert.Title}", $"previous owner {previous}");
        TempData["Success"] = "The escalation is back in the SOC 2 queue.";
        return BackTo(returnUrl, id);
    }

    /// <summary>The owner's decision on an escalated alert; it also sets the matching status.</summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Verdict(long id, EscalationVerdict? verdict, string? note,
        [FromServices] NotificationService notifications)
    {
        var me = await userManager.GetUserAsync(User);
        var alert = await db.Alerts.FirstOrDefaultAsync(a => a.Id == id);
        if (alert is null || me is null)
            return NotFound();
        if (verdict is not { } v || !Enum.IsDefined(v))
        {
            TempData["Error"] = "Choose a verdict.";
            return RedirectToAction(nameof(Details), new { id });
        }
        if (!SocPermissions.CanGiveVerdict(User.IsInRole(Roles.Admin), me.Tier, alert, me.Id))
        {
            await audit.WriteAsync("Alert.Verdict.Denied", $"#{id} {alert.Title}", v.ToString());
            TempData["Error"] = "Only the SOC 2 analyst who took this escalation can give or change its verdict.";
            return RedirectToAction(nameof(Details), new { id });
        }

        var changed = alert.Verdict is { } old && old != v ? $" (was {SocPermissions.Label(old)})" : "";
        alert.Verdict = v;
        alert.VerdictAt = DateTime.UtcNow;
        alert.VerdictBy = User.Identity?.Name;
        alert.Status = SocPermissions.StatusFor(v);
        var cleanNote = string.IsNullOrWhiteSpace(note) ? null : Cut(AuditLog.Clean(note.Trim())!, 1500);
        AddEvent(id, me, "verdict", $"Verdict: {SocPermissions.Label(v)}{changed}." + (cleanNote is null ? "" : " " + cleanNote));
        await db.SaveChangesAsync();

        await notifications.NotifyUserAsync(alert.EscalatedById, me.Id, "verdict",
            $"{NotificationService.DisplayName(me)}: {SocPermissions.Label(v)} on alert #{id}", alert.Title, NotificationService.AlertLink(id));
        await audit.WriteAsync("Alert.Verdict", $"#{id} {alert.Title}", $"{SocPermissions.Label(v)}{changed}");
        logger.LogInformation("User {User} gave verdict {Verdict} on alert {Id}", User.Identity?.Name, v, id);
        TempData["Success"] = $"Verdict saved: {SocPermissions.Label(v)}.";
        return RedirectToAction(nameof(Details), new { id });
    }

    /// <summary>Any analyst can add a comment, e.g. a second opinion on someone else's escalation.</summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Comment(long id, string? text, [FromServices] NotificationService notifications)
    {
        var me = await userManager.GetUserAsync(User);
        var alert = await db.Alerts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == id);
        if (alert is null || me is null)
            return NotFound();
        if (string.IsNullOrWhiteSpace(text))
        {
            TempData["Error"] = "Write a comment first.";
            return RedirectToAction(nameof(Details), new { id });
        }

        AddEvent(id, me, "comment", Cut(AuditLog.Clean(text.Trim())!, 2000)!);
        await db.SaveChangesAsync();
        // The owner hears about second opinions on their escalation.
        if (SocPermissions.IsEscalated(alert))
            await notifications.NotifyUserAsync(alert.AssignedToId, me.Id, "comment",
                $"{NotificationService.DisplayName(me)} commented on your escalation #{id}", Cut(text.Trim(), 160), NotificationService.AlertLink(id));
        await audit.WriteAsync("Alert.Comment", $"#{id} {alert.Title}");
        TempData["Success"] = "Comment added.";
        return Redirect(Url.Action(nameof(Details), new { id }) + "#comments");
    }

    private void AddEvent(long alertId, AppUser? author, string kind, string text) =>
        db.AlertComments.Add(new AlertComment
        {
            AlertId = alertId,
            AuthorId = author?.Id,
            AuthorName = NotificationService.DisplayName(author, User.Identity?.Name),
            Kind = kind,
            Text = text
        });

    private IActionResult BackTo(string? returnUrl, long id) =>
        SessionSlots.IsLocalToCurrentSlot(Request, returnUrl)
            ? LocalRedirect(returnUrl!)
            : RedirectToAction(nameof(Details), new { id });

    private static string? Cut(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];

    /// <summary>Exports the alerts matching the current filters as CSV (opens in Excel).</summary>
    [HttpGet]
    public async Task<IActionResult> Export(AlertStatus? status, Severity? severity, AttackType? attackType,
        string? ip, int? logFileId, CancellationToken ct, bool escalated = false)
    {
        var filtered = Filter(status, severity, attackType, ip, logFileId, escalated);
        var count = await filtered.CountAsync(ct);
        var ips = await filtered.Select(a => a.SourceIp).Distinct().ToListAsync(ct);
        var ipInfo = await db.IpInfos.AsNoTracking()
            .Where(i => ips.Contains(i.Ip))
            .ToDictionaryAsync(i => i.Ip, ct);

        logger.LogInformation("User {User} exported {Count} alerts to CSV", User.Identity?.Name, count);
        await audit.WriteAsync("Alerts.ExportCsv", $"{count} alerts",
            $"status={status} severity={severity} type={attackType} ip={ip} file={logFileId}", ct);

        // Streamed row by row (no whole file in memory). UTF-8 with BOM so Excel shows non-ASCII characters correctly.
        Response.ContentType = "text/csv; charset=utf-8";
        Response.Headers.ContentDisposition = $"attachment; filename=\"alerts-{DateTime.Now:yyyyMMdd-HHmm}.csv\"";
        await using var writer = new StreamWriter(Response.Body, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true), 64 * 1024);
        await writer.WriteAsync("Id,Severity,Status,AttackType,Rule,SourceIp,Country,City,AbuseScore,Events,FirstSeen,LastSeen,LogFile,AssignedTo,Notes\r\n");
        var csv = new StringBuilder();
        await foreach (var a in Sort(filtered).Include(a => a.Rule).AsAsyncEnumerable().WithCancellation(ct))
        {
            ipInfo.TryGetValue(a.SourceIp, out var info);
            csv.Clear();
            csv.AppendJoin(',',
                a.Id.ToString(),
                Format.Csv(a.Severity.ToString()),
                Format.Csv(a.Status.ToString()),
                Format.Csv(Format.AttackLabel(a.AttackType)),
                Format.Csv(a.Rule?.Name),
                Format.Csv(a.SourceIp),
                Format.Csv(info?.CountryCode),
                Format.Csv(info?.City),
                info?.AbuseScore?.ToString() ?? "",
                a.EventCount.ToString(),
                Format.Csv(a.FirstSeen.ToString("yyyy-MM-dd HH:mm:ss zzz")),
                Format.Csv(a.LastSeen.ToString("yyyy-MM-dd HH:mm:ss zzz")),
                Format.Csv(a.LogFile?.FileName),
                Format.Csv(a.AssignedTo?.Email),
                Format.Csv(a.Notes));
            csv.Append("\r\n");
            await writer.WriteAsync(csv, ct);
        }
        await writer.FlushAsync(ct);
        return new EmptyResult();
    }

    private IQueryable<Alert> Filter(AlertStatus? status, Severity? severity, AttackType? attackType, string? ip, int? logFileId,
        bool escalated = false)
    {
        var query = db.Alerts.AsNoTracking().Include(a => a.LogFile).Include(a => a.AssignedTo).AsQueryable();
        if (status.HasValue) query = query.Where(a => a.Status == status.Value);
        if (severity.HasValue) query = query.Where(a => a.Severity == severity.Value);
        if (attackType.HasValue) query = query.Where(a => a.AttackType == attackType.Value);
        if (!string.IsNullOrWhiteSpace(ip)) query = query.Where(a => a.SourceIp == ip.Trim());
        if (logFileId.HasValue) query = query.Where(a => a.LogFileId == logFileId.Value);
        // Escalated by SOC 1 and still open: the SOC 2 work queue.
        if (escalated) query = query.Where(a => a.EscalatedAt != null
                                                && (a.Status == AlertStatus.New || a.Status == AlertStatus.Investigating));
        return query;
    }

    // Severity and status are stored as text, so sort by explicit ranks (open + critical first).
    private static IQueryable<Alert> Sort(IQueryable<Alert> query) => query
        .OrderBy(a => a.Status == AlertStatus.New ? 0 : a.Status == AlertStatus.Investigating ? 1 : 2)
        .ThenByDescending(a => a.Severity == Severity.Critical ? 3 : a.Severity == Severity.High ? 2 : a.Severity == Severity.Medium ? 1 : 0)
        .ThenByDescending(a => a.LastSeen)
        .ThenByDescending(a => a.Id);   // unique tie-breaker: stable pages
}
