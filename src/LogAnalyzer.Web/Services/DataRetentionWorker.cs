using LogAnalyzer.Web.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace LogAnalyzer.Web.Services;

/// <summary>
/// Privacy: threat-intel answers and GeoIP data about client addresses are not kept forever. Once a day it removes
/// reputation answers older than <see cref="EnrichmentOptions.RetentionDays"/>, answers about IPs that no alert
/// refers to any more (e.g. after their log file was deleted) once their cache time is over, and GeoIP rows of such
/// orphaned IPs.
/// </summary>
public sealed class DataRetentionWorker(
    IServiceScopeFactory scopeFactory,
    IOptions<EnrichmentOptions> options,
    ILogger<DataRetentionWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
            using var timer = new PeriodicTimer(TimeSpan.FromHours(24));
            do
            {
                try
                {
                    using var scope = scopeFactory.CreateScope();
                    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                    var (reputations, ipInfos) = await PurgeAsync(db, options.Value, DateTime.UtcNow, stoppingToken);
                    if (reputations + ipInfos > 0)
                        logger.LogInformation("Retention: removed {Reputations} threat-intel answers and {IpInfos} GeoIP rows",
                            reputations, ipInfos);
                }
                catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
                {
                    logger.LogWarning(ex, "Retention clean-up failed; it runs again tomorrow");
                }
            } while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    public static async Task<(int Reputations, int IpInfos)> PurgeAsync(AppDbContext db, EnrichmentOptions o, DateTime now, CancellationToken ct)
    {
        var expired = now.AddDays(-Math.Max(1, o.RetentionDays));
        var cacheOver = now.AddDays(-Math.Max(0, o.CacheDays));
        var reputations = await db.IpReputations
            .Where(r => r.CheckedAt < expired
                        || (r.CheckedAt < cacheOver && !db.Alerts.Any(a => a.SourceIp == r.Ip)))
            .ExecuteDeleteAsync(ct);
        var ipInfos = await db.IpInfos
            .Where(i => !db.Alerts.Any(a => a.SourceIp == i.Ip) && !db.IpReputations.Any(r => r.Ip == i.Ip))
            .ExecuteDeleteAsync(ct);
        return (reputations, ipInfos);
    }
}
