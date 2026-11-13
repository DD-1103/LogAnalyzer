using System.Text;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Helpers;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Controllers;

public class AlertsController(AppDbContext db, UserManager<AppUser> userManager, ILogger<AlertsController> logger) : Controller
{
    private const int PageSize = 25;
    private const int MaxEvidenceShown = 200;

    public async Task<IActionResult> Index(AlertStatus? status, Severity? severity, AttackType? attackType,
        string? ip, int? logFileId, int page = 1)
    {
        // Mark alerts as "seen" for the nav badge, but remember the previous visit to highlight new rows.
        var userId = userManager.GetUserId(User);
        var previousSeenAt = await db.Users.Where(u => u.Id == userId).Select(u => u.AlertsSeenAt).FirstOrDefaultAsync();
        await db.Users.Where(u => u.Id == userId)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.AlertsSeenAt, DateTime.UtcNow));

        var query = Filter(status, severity, attackType, ip, logFileId);

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
            Page = page,
            TotalPages = totalPages,
            TotalCount = count,
            PreviousSeenAt = previousSeenAt
        });
    }

    public async Task<IActionResult> Details(long id)
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

        return View(new AlertDetailsViewModel
        {
            Alert = alert,
            Evidence = evidence,
            EvidenceShown = evidence.Count,
            IpInfo = await db.IpInfos.AsNoTracking().FirstOrDefaultAsync(i => i.Ip == alert.SourceIp)
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
            TempData["Error"] = "Notes are too long (max 4000 characters).";
            return RedirectToAction(nameof(Details), new { id });
        }

        var oldStatus = alert.Status;
        alert.Status = model.Status;
        alert.Notes = string.IsNullOrWhiteSpace(model.Notes) ? null : model.Notes.Trim();

        // The analyst who picks the alert up becomes its owner.
        if (model.Status == AlertStatus.Investigating && alert.AssignedToId is null)
            alert.AssignedToId = userManager.GetUserId(User);

        await db.SaveChangesAsync();
        logger.LogInformation("User {User} changed alert {Id} from {Old} to {New}",
            User.Identity?.Name, id, oldStatus, model.Status);

        TempData["Success"] = "Alert updated.";
        return RedirectToAction(nameof(Details), new { id });
    }

    /// <summary>Exports the alerts matching the current filters as CSV (opens in Excel).</summary>
    public async Task<IActionResult> Export(AlertStatus? status, Severity? severity, AttackType? attackType,
        string? ip, int? logFileId, CancellationToken ct)
    {
        var alerts = await Sort(Filter(status, severity, attackType, ip, logFileId))
            .Include(a => a.Rule)
            .ToListAsync(ct);

        var ips = alerts.Select(a => a.SourceIp).Distinct().ToList();
        var ipInfo = await db.IpInfos.AsNoTracking()
            .Where(i => ips.Contains(i.Ip))
            .ToDictionaryAsync(i => i.Ip, ct);

        var csv = new StringBuilder();
        csv.AppendLine("Id,Severity,Status,AttackType,Rule,SourceIp,Country,City,AbuseScore,Events,FirstSeen,LastSeen,LogFile,AssignedTo,Notes");
        foreach (var a in alerts)
        {
            ipInfo.TryGetValue(a.SourceIp, out var info);
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
            csv.AppendLine();
        }

        logger.LogInformation("User {User} exported {Count} alerts to CSV", User.Identity?.Name, alerts.Count);

        // UTF-8 with BOM so Excel shows non-ASCII characters correctly
        var bytes = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(csv.ToString())).ToArray();
        return File(bytes, "text/csv", $"alerts-{DateTime.Now:yyyyMMdd-HHmm}.csv");
    }

    private IQueryable<Alert> Filter(AlertStatus? status, Severity? severity, AttackType? attackType, string? ip, int? logFileId)
    {
        var query = db.Alerts.AsNoTracking().Include(a => a.LogFile).Include(a => a.AssignedTo).AsQueryable();
        if (status.HasValue) query = query.Where(a => a.Status == status.Value);
        if (severity.HasValue) query = query.Where(a => a.Severity == severity.Value);
        if (attackType.HasValue) query = query.Where(a => a.AttackType == attackType.Value);
        if (!string.IsNullOrWhiteSpace(ip)) query = query.Where(a => a.SourceIp == ip.Trim());
        if (logFileId.HasValue) query = query.Where(a => a.LogFileId == logFileId.Value);
        return query;
    }

    // Severity and status are stored as text, so sort by explicit ranks (open + critical first).
    private static IQueryable<Alert> Sort(IQueryable<Alert> query) => query
        .OrderBy(a => a.Status == AlertStatus.New ? 0 : a.Status == AlertStatus.Investigating ? 1 : 2)
        .ThenByDescending(a => a.Severity == Severity.Critical ? 3 : a.Severity == Severity.High ? 2 : a.Severity == Severity.Medium ? 1 : 0)
        .ThenByDescending(a => a.LastSeen);
}
