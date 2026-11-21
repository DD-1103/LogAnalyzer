using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Controllers;

/// <summary>
/// The bell. Every query is limited to the signed-in user's own notifications (no id from another user works).
/// Opening the bell marks everything as read; only read notifications can be deleted.
/// </summary>
public class NotificationsController(AppDbContext db, UserManager<AppUser> userManager) : Controller
{
    private const int ListSize = 30;

    private string Me => userManager.GetUserId(User)!;

    private IQueryable<Notification> Mine => db.Notifications.Where(n => n.UserId == Me);

    /// <summary>Full page (works without JavaScript); opening it marks everything as read.</summary>
    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var items = await Mine.AsNoTracking().OrderByDescending(n => n.CreatedAt).Take(200).ToListAsync(ct);
        await MarkAllReadAsync(ct);
        return View(items);
    }

    /// <summary>Latest notifications for the bell menu (JSON, rendered with textContent by notifications.js).</summary>
    [HttpGet]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var items = await Mine.AsNoTracking()
            .OrderByDescending(n => n.CreatedAt)
            .Take(ListSize)
            .Select(n => new { n.Id, n.Title, n.Body, n.Link, n.Kind, n.CreatedAt, read = n.ReadAt != null })
            .ToListAsync(ct);
        return Json(items.Select(n => new
        {
            // Stored app-relative; returned with this tab's session prefix (/s/n) so a click stays in the session.
            id = n.Id, title = n.Title, body = n.Body, link = SessionSlots.AppLink(Request.PathBase, n.Link), kind = n.Kind,
            createdAt = DateTime.SpecifyKind(n.CreatedAt, DateTimeKind.Utc), read = n.read
        }));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> MarkRead(CancellationToken ct)
    {
        var count = await MarkAllReadAsync(ct);
        return Json(new { marked = count });
    }

    /// <summary>Deletes one notification the user has already seen.</summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(long id, CancellationToken ct)
    {
        var deleted = await Mine.Where(n => n.Id == id && n.ReadAt != null).ExecuteDeleteAsync(ct);
        if (IsJson())
            return deleted == 1 ? Json(new { deleted }) : Conflict(new { error = "Open the notification first." });
        return RedirectToAction(nameof(Index));
    }

    /// <summary>Deletes every notification the user has already seen.</summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ClearRead(CancellationToken ct)
    {
        var deleted = await Mine.Where(n => n.ReadAt != null).ExecuteDeleteAsync(ct);
        return IsJson() ? Json(new { deleted }) : RedirectToAction(nameof(Index));
    }

    private Task<int> MarkAllReadAsync(CancellationToken ct) =>
        Mine.Where(n => n.ReadAt == null).ExecuteUpdateAsync(s => s.SetProperty(n => n.ReadAt, DateTime.UtcNow), ct);

    private bool IsJson() =>
        Request.Headers.Accept.ToString().Contains("application/json", StringComparison.OrdinalIgnoreCase);
}
