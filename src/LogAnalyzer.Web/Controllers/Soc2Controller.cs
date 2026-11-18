using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Controllers;

/// <summary>
/// SOC 2 hub (/Soc2): every alert escalated by SOC 1, who owns it and its verdict. Only SOC 2 analysts and
/// administrators can open it; the tier is read from the database, so a promotion applies at once.
/// </summary>
public class Soc2Controller(AppDbContext db, UserManager<AppUser> userManager) : Controller
{
    private const int MaxItems = 500;
    private static readonly string[] Views = ["all", "waiting", "progress", "mine", "decided"];

    [HttpGet]
    public async Task<IActionResult> Index(string? view, CancellationToken ct)
    {
        var me = await userManager.GetUserAsync(User);
        if (me is null || !SocPermissions.IsSoc2(User.IsInRole(Roles.Admin), me.Tier))
            return Forbid();
        view = Views.Contains(view) ? view! : "all";

        var alerts = await db.Alerts.AsNoTracking()
            .Include(a => a.AssignedTo)
            .Where(a => a.EscalatedAt != null)
            .OrderByDescending(a => a.EscalatedAt)
            .Take(MaxItems)
            .ToListAsync(ct);
        var ids = alerts.Select(a => a.Id).ToList();
        var comments = await db.AlertComments.AsNoTracking()
            .Where(c => ids.Contains(c.AlertId) && c.Kind == "comment")
            .GroupBy(c => c.AlertId)
            .Select(g => new { g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Key, x => x.Count, ct);

        var items = alerts.Select(a => new Soc2HubItem(
                a,
                SocPermissions.StateOf(a),
                comments.GetValueOrDefault(a.Id),
                a.AssignedTo is null ? null : NotificationService.DisplayName(a.AssignedTo),
                SocPermissions.IsOwner(a, me.Id)))
            .ToList();

        var model = new Soc2HubViewModel
        {
            View = view,
            Waiting = items.Count(i => i.State == SocPermissions.HubState.Waiting),
            InProgress = items.Count(i => i.State == SocPermissions.HubState.InProgress),
            Decided = items.Count(i => i.State == SocPermissions.HubState.Decided),
            Mine = items.Count(i => i.IsMine && i.State != SocPermissions.HubState.Decided),
            Items = items
                .Where(i => view switch
                {
                    "waiting" => i.State == SocPermissions.HubState.Waiting,
                    "progress" => i.State == SocPermissions.HubState.InProgress,
                    "mine" => i.IsMine,
                    "decided" => i.State == SocPermissions.HubState.Decided,
                    _ => true
                })
                // Waiting first (needs an owner), then in progress, then decided; most severe and newest first.
                .OrderBy(i => (int)i.State)
                .ThenByDescending(i => (int)i.Alert.Severity)
                .ThenByDescending(i => i.Alert.EscalatedAt)
                .ToList()
        };
        return View(model);
    }
}
