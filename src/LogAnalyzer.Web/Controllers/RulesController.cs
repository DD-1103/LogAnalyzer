using System.Security.Claims;
using LogAnalyzer.Web.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Controllers;

public class RulesController(AppDbContext db, ILogger<RulesController> logger) : Controller
{
    public async Task<IActionResult> Index()
    {
        // Clears the Rules nav badge for this user.
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        await db.Users.Where(u => u.Id == userId)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.RulesSeenAt, DateTime.UtcNow));

        var rules = await db.DetectionRules.AsNoTracking()
            .OrderBy(r => r.Kind).ThenBy(r => r.Name)
            .ToListAsync();

        ViewBag.AlertCounts = await db.Alerts
            .GroupBy(a => a.RuleId)
            .Select(g => new { g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Key, x => x.Count);

        return View(rules);
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
        logger.LogInformation("User {User} {Action} rule {Rule}",
            User.Identity?.Name, rule.IsEnabled ? "enabled" : "disabled", rule.Name);

        TempData["Success"] = $"Rule \"{rule.Name}\" {(rule.IsEnabled ? "enabled" : "disabled")}. " +
                              "Re-run detection on a log file to apply it to existing data.";
        return RedirectToAction(nameof(Index));
    }
}
