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
                UserName = Cut(Clean(userName), 256),
                Action = Cut(Clean(action), 100)!,
                Target = Cut(Clean(target), 300),
                Details = Cut(Clean(details), 2000),
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

    /// <summary>
    /// Replaces control characters (CR, LF, ESC, NUL ...) with spaces, so text typed by users or taken from logs cannot
    /// forge extra lines in the console log or the audit trail. Use it for user input passed to ILogger as well.
    /// </summary>
    public static string? Clean(string? value)
    {
        if (value is null || !value.Any(char.IsControl))
            return value;
        return string.Create(value.Length, value, (span, v) =>
        {
            for (var i = 0; i < v.Length; i++)
                span[i] = char.IsControl(v[i]) ? ' ' : v[i];
        });
    }
}
