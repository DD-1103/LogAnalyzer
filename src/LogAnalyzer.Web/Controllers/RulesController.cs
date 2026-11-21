using System.Security.Claims;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Controllers;

/// <summary>
/// Detection rules. Everyone can view them; only admins can create, edit, test, enable/disable or delete (FR4).
/// </summary>
public class RulesController(AppDbContext db, IAuditLog audit, ILogger<RulesController> logger) : Controller
{
    /// <param name="source">Optional filter: "web" or "firewall" (all rules when empty).</param>
    [HttpGet]
    public async Task<IActionResult> Index(string? source)
    {
        // Clears the Rules nav badge for this user.
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        await db.Users.Where(u => u.Id == userId)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.RulesSeenAt, DateTime.UtcNow));

        // Few rules: sorted in memory (AppliesTo is stored as text, so SQL would put "Firewall" before "WebAccess").
        var all = (await db.DetectionRules.AsNoTracking().ToListAsync())
            .OrderBy(r => r.AppliesTo).ThenBy(r => r.Kind).ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
        LogSource? filter = source?.ToLowerInvariant() switch
        {
            "web" => LogSource.WebAccess,
            "firewall" => LogSource.Firewall,
            _ => null
        };
        ViewBag.Source = filter;
        ViewBag.WebCount = all.Count(r => r.AppliesTo == LogSource.WebAccess);
        ViewBag.FirewallCount = all.Count(r => r.AppliesTo == LogSource.Firewall);
        ViewBag.Total = all.Count;
        ViewBag.Enabled = all.Count(r => r.IsEnabled);
        var rules = filter is null ? all : all.Where(r => r.AppliesTo == filter).ToList();

        ViewBag.AlertCounts = await db.Alerts
            .GroupBy(a => a.RuleId)
            .Select(g => new { g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Key, x => x.Count);

        return View(rules);
    }

    [HttpGet]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Create(RuleKind kind = RuleKind.Signature, LogSource source = LogSource.WebAccess)
    {
        if (!Enum.IsDefined(kind) || !Enum.IsDefined(source))
            return BadRequest();
        // Distinct-count rules only exist for firewall logs, anomaly rules only for web logs.
        if (kind == RuleKind.DistinctCount)
            source = LogSource.Firewall;
        if (kind == RuleKind.Anomaly)
            source = LogSource.WebAccess;
        var firewall = source == LogSource.Firewall;

        var model = new RuleFormModel
        {
            Kind = kind,
            AppliesTo = source,
            Severity = Severity.Medium,
            Field = kind switch
            {
                RuleKind.DistinctCount => RuleField.DestinationPort,
                RuleKind.Signature when firewall => RuleField.ThreatName,
                _ when firewall => RuleField.Message,
                _ => RuleField.Url
            },
            WindowSeconds = kind switch { RuleKind.Threshold => firewall ? 300 : 60, RuleKind.DistinctCount => 60, _ => null },
            Threshold = kind switch { RuleKind.Threshold => 20, RuleKind.Anomaly => 20, RuleKind.DistinctCount => 15, _ => null },
            ScoreThreshold = kind == RuleKind.Anomaly ? 0.62 : null,
            AttackType = kind switch
            {
                RuleKind.Anomaly => AttackType.Anomaly,
                RuleKind.DistinctCount => AttackType.PortScan,
                RuleKind.Threshold when firewall => AttackType.BlockedTraffic,
                RuleKind.Signature when firewall => AttackType.Intrusion,
                _ => AttackType.SqlInjection
            }
        };
        await FillLogFilesAsync(model);
        return View("Edit", model);
    }

    [HttpGet]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Edit(int id)
    {
        var rule = await db.DetectionRules.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id);
        if (rule is null)
            return NotFound();
        var model = RuleFormModel.From(rule);
        await FillLogFilesAsync(model);
        return View(model);
    }

    /// <summary>Saves a new or edited rule. The "test" button posts here too, with intent=test.</summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Save(RuleFormModel model, string? intent, [FromServices] RuleTester tester, CancellationToken ct)
    {
        model.Normalize();
        var rule = model.ToRule();

        foreach (var error in RuleValidator.Validate(rule))
            ModelState.AddModelError(string.Empty, error);
        if (await db.DetectionRules.AnyAsync(r => r.Name == model.Name && r.Id != (model.Id ?? 0), ct))
            ModelState.AddModelError(nameof(model.Name), "Another rule already has this name.");

        await FillLogFilesAsync(model);

        if (intent == "test")
        {
            if (model.TestLogFileId is null)
                ModelState.AddModelError(nameof(model.TestLogFileId), "Choose a log file to test against.");
            if (ModelState.IsValid)
                model.TestResult = await tester.TestAsync(rule, model.TestLogFileId!.Value, ct);
            return View("Edit", model);
        }

        if (!ModelState.IsValid)
            return View("Edit", model);

        if (model.Id is null)
        {
            db.DetectionRules.Add(rule);
            await db.SaveChangesAsync(ct);
            await audit.WriteAsync("Rule.Create", rule.Name, $"{rule.AppliesTo} {rule.Kind} {rule.AttackType} {rule.Severity}", ct);
            logger.LogInformation("User {User} created rule {Rule}", User.Identity?.Name, rule.Name);
            TempData["Success"] = $"Rule \"{rule.Name}\" created. Re-run detection on a log file to apply it to existing data.";
        }
        else
        {
            var existing = await db.DetectionRules.FirstOrDefaultAsync(r => r.Id == model.Id, ct);
            if (existing is null)
                return NotFound();
            var before = Describe(existing);
            model.ApplyTo(existing);
            await db.SaveChangesAsync(ct);
            await audit.WriteAsync("Rule.Edit", existing.Name, $"before: {before} | after: {Describe(existing)}", ct);
            logger.LogInformation("User {User} edited rule {Rule}", User.Identity?.Name, existing.Name);
            TempData["Success"] = $"Rule \"{existing.Name}\" saved. Re-run detection on a log file to apply the change to existing data.";
        }
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Toggle(int id)
    {
        var rule = await db.DetectionRules.FirstOrDefaultAsync(r => r.Id == id);
        if (rule is null)
            return NotFound();

        rule.IsEnabled = !rule.IsEnabled;
        await db.SaveChangesAsync();
        await audit.WriteAsync(rule.IsEnabled ? "Rule.Enable" : "Rule.Disable", rule.Name);
        logger.LogInformation("User {User} {Action} rule {Rule}",
            User.Identity?.Name, rule.IsEnabled ? "enabled" : "disabled", rule.Name);

        TempData["Success"] = $"Rule \"{rule.Name}\" {(rule.IsEnabled ? "enabled" : "disabled")}. " +
                              "Re-run detection on a log file to apply it to existing data.";
        return RedirectToAction(nameof(Index));
    }

    /// <summary>Deletes a rule that never produced alerts. Rules with alerts are kept for traceability: disable them instead.</summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Delete(int id)
    {
        var rule = await db.DetectionRules.FirstOrDefaultAsync(r => r.Id == id);
        if (rule is null)
            return NotFound();

        // While a file is analysed its old alerts are temporarily gone: a rule could look unused although it is not.
        if (await db.LogFiles.AnyAsync(f => f.Status == LogFileStatus.Processing || f.Status == LogFileStatus.Analyzing
                                            || f.Status == LogFileStatus.Pending))
        {
            TempData["Error"] = "A log file is being processed. Delete the rule when it has finished (or disable it now).";
            return RedirectToAction(nameof(Index));
        }

        var alerts = await db.Alerts.CountAsync(a => a.RuleId == id);
        if (alerts > 0)
        {
            TempData["Error"] = $"\"{rule.Name}\" has {alerts} alert(s) and cannot be deleted (evidence must stay traceable). Disable it instead.";
            return RedirectToAction(nameof(Index));
        }

        db.DetectionRules.Remove(rule);
        await db.SaveChangesAsync();
        await audit.WriteAsync("Rule.Delete", rule.Name, Describe(rule));
        logger.LogInformation("User {User} deleted rule {Rule}", User.Identity?.Name, rule.Name);
        TempData["Success"] = $"Rule \"{rule.Name}\" deleted.";
        return RedirectToAction(nameof(Index));
    }

    /// <summary>
    /// Completed files of both kinds, each tagged with its source: the view offers only the files of the rule's kind
    /// (rule-form.js switches the list when "Applies to" changes) and RuleTester refuses a file of the other kind.
    /// </summary>
    private async Task FillLogFilesAsync(RuleFormModel model)
    {
        model.LogFiles = await db.LogFiles.AsNoTracking()
            .Where(f => f.Status == LogFileStatus.Completed)
            .OrderByDescending(f => f.UploadedAt)
            .Select(f => new LogFileOption(f.Id, f.FileName, f.ParsedLines, f.Source))
            .ToListAsync();
        if (model.TestLogFileId is int chosen && !model.LogFiles.Any(f => f.Id == chosen && f.Source == model.AppliesTo))
            model.TestLogFileId = null;
        model.TestLogFileId ??= model.LogFiles.FirstOrDefault(f => f.Source == model.AppliesTo)?.Id;
    }

    private static string Describe(DetectionRule r) => r.Kind switch
    {
        RuleKind.Signature => $"{r.Severity} {r.Field} ~ {r.Pattern}",
        RuleKind.Threshold => $"{r.Severity} >= {r.Threshold} in {r.WindowSeconds}s method={r.MethodFilter} status={r.StatusFilter} path={r.PathPattern}",
        RuleKind.DistinctCount => $"{r.Severity} >= {r.Threshold} distinct {r.Field} in {r.WindowSeconds}s",
        _ => $"{r.Severity} min requests {r.Threshold}, score >= {r.ScoreThreshold}"
    } + (r.AppliesTo == LogSource.Firewall
        ? $" [firewall actions={r.ActionFilter ?? "any"} ports={r.PortFilter ?? "any"}" +
          (r.Kind == RuleKind.Signature || r.Pattern is null ? "]" : $" {r.Field} ~ {r.Pattern}]")
        : "") + (r.IsEnabled ? "" : " (disabled)");
}
