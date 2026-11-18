using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Services;

/// <summary>
/// Creates in-app notifications (the bell). Escalations go to every active SOC 2 analyst; when no SOC 2 analyst
/// exists yet they go to the administrators, so an escalation is never silently lost. The person who acted is
/// never notified about their own action.
/// </summary>
public sealed class NotificationService(AppDbContext db, UserManager<AppUser> userManager, ILogger<NotificationService> logger)
{
    public const int MaxPerUser = 200;

    public static string AlertLink(long alertId) => $"/Alerts/Details/{alertId}";

    /// <summary>Notifies the SOC 2 team that <paramref name="actorName"/> escalated an alert.</summary>
    public async Task<int> NotifySoc2Async(Alert alert, string? actorId, string actorName, CancellationToken ct = default)
    {
        var recipients = await db.Users.AsNoTracking()
            .Where(u => u.Tier == AnalystTier.Soc2 && !u.IsDisabled && u.Id != actorId)
            .Select(u => u.Id)
            .ToListAsync(ct);
        if (recipients.Count == 0)
            recipients = (await userManager.GetUsersInRoleAsync(Roles.Admin))
                .Where(u => !u.IsDisabled && u.Id != actorId).Select(u => u.Id).ToList();

        var body = string.IsNullOrWhiteSpace(alert.EscalationReason)
            ? alert.Title
            : $"{alert.Title}. Reason: {alert.EscalationReason}";
        foreach (var userId in recipients)
            Add(userId, "escalation", $"{actorName} escalated alert #{alert.Id} to SOC 2", body, AlertLink(alert.Id));
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Escalation of alert {Id} notified to {Count} user(s)", alert.Id, recipients.Count);
        return recipients.Count;
    }

    /// <summary>Notifies one user (unless it is the actor themselves or the account no longer exists).</summary>
    public async Task NotifyUserAsync(string? userId, string? actorId, string kind, string title, string? body, string? link,
        CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(userId) || userId == actorId)
            return;
        if (!await db.Users.AnyAsync(u => u.Id == userId && !u.IsDisabled, ct))
            return;
        Add(userId, kind, title, body, link);
        await db.SaveChangesAsync(ct);
    }

    private void Add(string userId, string kind, string title, string? body, string? link) =>
        db.Notifications.Add(new Notification
        {
            UserId = userId,
            Kind = kind,
            Title = Cut(AuditLog.Clean(title), 200)!,
            Body = Cut(AuditLog.Clean(body), 500),
            Link = link is not null && link.StartsWith('/') && !link.StartsWith("//") ? Cut(link, 300) : null
        });

    /// <summary>Display name of an account: full name, else e-mail.</summary>
    public static string DisplayName(AppUser? user, string? fallback = null) =>
        user is null ? fallback ?? "Someone" : string.IsNullOrWhiteSpace(user.FullName) ? user.Email ?? fallback ?? "Someone" : user.FullName;

    private static string? Cut(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];
}
