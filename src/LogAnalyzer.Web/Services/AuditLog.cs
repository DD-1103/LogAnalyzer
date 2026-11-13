using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;

namespace LogAnalyzer.Web.Services;

/// <summary>Records security-relevant user actions (who did what, when, from where) in the AuditEntries table.</summary>
public interface IAuditLog
{
    Task WriteAsync(string action, string? target, string? details = null, CancellationToken ct = default);

    /// <summary>For events without a signed-in user yet (e.g. failed logins).</summary>
    Task WriteAsync(string action, string? target, string? details, string? userName, CancellationToken ct = default);
}

public sealed class AuditLog(
    IServiceScopeFactory scopeFactory,
    IHttpContextAccessor httpContext,
    ILogger<AuditLog> logger) : IAuditLog
{
    public Task WriteAsync(string action, string? target, string? details = null, CancellationToken ct = default) =>
        WriteAsync(action, target, details, httpContext.HttpContext?.User.Identity?.Name, ct);

    public async Task WriteAsync(string action, string? target, string? details, string? userName, CancellationToken ct = default)
    {
        try
        {
            // Own DbContext, so an audit write never saves (or is blocked by) the caller's pending changes.
            using var scope = scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.AuditEntries.Add(new AuditEntry
            {
                UserName = Cut(userName, 256),
                Action = Cut(action, 100)!,
                Target = Cut(target, 300),
                Details = Cut(details, 2000),
                IpAddress = Cut(httpContext.HttpContext?.Connection.RemoteIpAddress?.ToString(), 45)
            });
            await db.SaveChangesAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            // Auditing must never break the user's action.
            logger.LogError(ex, "Could not write audit entry {Action} {Target}", action, target);
        }
    }

    private static string? Cut(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];
}
