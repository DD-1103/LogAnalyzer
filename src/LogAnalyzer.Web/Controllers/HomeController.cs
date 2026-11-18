using System.Security.Claims;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Controllers;

public class HomeController(AppDbContext db) : Controller
{
    [HttpGet]
    public async Task<IActionResult> Index(int? logFileId, [FromServices] DashboardService dashboard, CancellationToken ct)
    {
        var model = await dashboard.BuildAsync(logFileId, ct);
        return View(model);
    }

    /// <summary>Counts for the navigation badges (polled by the layout every few seconds).</summary>
    [HttpGet]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> NavCounts()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var seen = await db.Users.AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => new { u.AlertsSeenAt, u.RulesSeenAt })
            .FirstOrDefaultAsync();
        var alertsSince = seen?.AlertsSeenAt ?? DateTime.MinValue;
        var rulesSince = seen?.RulesSeenAt ?? DateTime.MinValue;

        var processing = await db.LogFiles.CountAsync(f =>
            f.Status == LogFileStatus.Pending || f.Status == LogFileStatus.Processing || f.Status == LogFileStatus.Analyzing);

        // Alerts created since this user last opened the Alerts page
        var newAlerts = await db.Alerts.CountAsync(a => a.CreatedAt > alertsSince);

        // Rules that produced alerts since this user last opened the Rules page
        var firingRules = await db.Alerts
            .Where(a => a.CreatedAt > rulesSince)
            .Select(a => a.RuleId)
            .Distinct()
            .CountAsync();

        // Bell: unread notifications. SOC 2 hub: escalations nobody has taken yet (only for SOC 2 / admins).
        var notifications = await db.Notifications.CountAsync(n => n.UserId == userId && n.ReadAt == null);
        var tier = await db.Users.AsNoTracking().Where(u => u.Id == userId).Select(u => u.Tier).FirstOrDefaultAsync();
        var soc2Waiting = SocPermissions.IsSoc2(User.IsInRole(Roles.Admin), tier)
            ? await db.Alerts.CountAsync(a => a.EscalatedAt != null && a.AssignedToId == null && a.Verdict == null)
            : 0;

        return Json(new { processing, newAlerts, firingRules, notifications, soc2Waiting });
    }

    [AllowAnonymous]
    // Re-executed by the exception handler with the original verb (GET or POST).
    [AcceptVerbs("GET", "HEAD", "POST")]
    [IgnoreAntiforgeryToken]
    public IActionResult Error() => View();
}
