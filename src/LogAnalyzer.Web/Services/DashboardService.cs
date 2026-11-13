using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Helpers;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.ViewModels;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Services;

/// <summary>Builds the dashboard statistics, optionally for a single log file.</summary>
public sealed class DashboardService(AppDbContext db, GeoIpLookup geo)
{
    private const int MaxFilledHours = 24 * 7; // fill empty hours only for spans up to one week

    public async Task<DashboardViewModel> BuildAsync(int? logFileId, CancellationToken ct = default)
    {
        var events = db.LogEvents.AsNoTracking().AsQueryable();
        var alertsQuery = db.Alerts.AsNoTracking().AsQueryable();
        var evidence = db.AlertEvidence.AsNoTracking().AsQueryable();
        if (logFileId.HasValue)
        {
            events = events.Where(e => e.LogFileId == logFileId);
            alertsQuery = alertsQuery.Where(a => a.LogFileId == logFileId);
            evidence = evidence.Where(e => e.Alert!.LogFileId == logFileId);
        }

        var model = new DashboardViewModel
        {
            LogFileId = logFileId,
            Files = await db.LogFiles.AsNoTracking().OrderByDescending(f => f.UploadedAt).ToListAsync(ct),
            LogFiles = logFileId.HasValue ? 1 : await db.LogFiles.CountAsync(ct),
            Events = await events.LongCountAsync(ct),
            EnabledRules = await db.DetectionRules.CountAsync(r => r.IsEnabled, ct),
            GeoIpAvailable = geo.IsAvailable,
            GeoIpSource = geo.SourceName
        };

        // ---- Alerts (small table, aggregated in memory) ----
        var alerts = await alertsQuery
            .Select(a => new { a.SourceIp, a.AttackType, a.Severity, a.Status, a.EventCount })
            .ToListAsync(ct);

        var open = alerts.Where(a => a.Status is AlertStatus.New or AlertStatus.Investigating).ToList();
        model.OpenAlerts = open.Count;
        model.OpenHighOrCritical = open.Count(a => a.Severity is Severity.High or Severity.Critical);

        model.BySeverity = Enum.GetValues<Severity>()
            .Reverse()
            .Select(s => new NameCount(s.ToString(), alerts.Count(a => a.Severity == s)))
            .ToList();

        model.ByAttackType = alerts
            .GroupBy(a => a.AttackType)
            .Select(g => new NameCount(Format.AttackLabel(g.Key), g.Sum(a => a.EventCount)))
            .OrderByDescending(x => x.Count)
            .ToList();

        // ---- Requests per hour: all vs. flagged as malicious ----
        var totalPerHour = await events
            .GroupBy(e => new { e.Timestamp.Year, e.Timestamp.Month, e.Timestamp.Day, e.Timestamp.Hour })
            .Select(g => new { g.Key.Year, g.Key.Month, g.Key.Day, g.Key.Hour, Count = g.Count() })
            .ToListAsync(ct);

        var flaggedPerHour = await events
            .Where(e => db.AlertEvidence.Any(x => x.LogEventId == e.Id))
            .GroupBy(e => new { e.Timestamp.Year, e.Timestamp.Month, e.Timestamp.Day, e.Timestamp.Hour })
            .Select(g => new { g.Key.Year, g.Key.Month, g.Key.Day, g.Key.Hour, Count = g.Count() })
            .ToListAsync(ct);

        var totals = totalPerHour.ToDictionary(x => new DateTime(x.Year, x.Month, x.Day, x.Hour, 0, 0), x => x.Count);
        var flagged = flaggedPerHour.ToDictionary(x => new DateTime(x.Year, x.Month, x.Day, x.Hour, 0, 0), x => x.Count);

        if (totals.Count > 0)
        {
            var first = totals.Keys.Min();
            var last = totals.Keys.Max();
            var hours = (int)(last - first).TotalHours + 1;
            var buckets = hours <= MaxFilledHours
                ? Enumerable.Range(0, hours).Select(i => first.AddHours(i))
                : totals.Keys.OrderBy(k => k);

            foreach (var hour in buckets)
            {
                model.HourLabels.Add(hour.ToString("dd/MM HH:00"));
                model.HourTotal.Add(totals.GetValueOrDefault(hour));
                model.HourMalicious.Add(flagged.GetValueOrDefault(hour));
            }
        }

        // ---- Top attacking IPs ----
        var eventsPerIp = await evidence
            .GroupBy(e => e.Alert!.SourceIp)
            .Select(g => new { Ip = g.Key, Events = g.Select(x => x.LogEventId).Distinct().Count() })
            .ToDictionaryAsync(x => x.Ip, x => x.Events, ct);

        var ips = alerts.Select(a => a.SourceIp).Distinct().ToList();
        var ipInfo = await db.IpInfos.AsNoTracking()
            .Where(i => ips.Contains(i.Ip))
            .ToDictionaryAsync(i => i.Ip, ct);

        var perIp = alerts
            .GroupBy(a => a.SourceIp)
            .Select(g =>
            {
                ipInfo.TryGetValue(g.Key, out var info);
                return new TopIp(
                    Ip: g.Key,
                    CountryCode: info?.CountryCode,
                    Country: info?.CountryName,
                    City: info?.City,
                    AbuseScore: info?.AbuseScore,
                    Alerts: g.Count(),
                    Events: eventsPerIp.GetValueOrDefault(g.Key),
                    MaxSeverity: g.Max(a => a.Severity),
                    AttackTypes: string.Join(", ", g.Select(a => Format.AttackLabel(a.AttackType)).Distinct()),
                    Latitude: info?.Latitude,
                    Longitude: info?.Longitude);
            })
            .OrderByDescending(x => x.MaxSeverity)
            .ThenByDescending(x => x.Events)
            .ToList();

        model.TopIps = perIp.Take(10).ToList();
        model.MapPoints = perIp
            .Where(p => p.Latitude.HasValue && p.Longitude.HasValue)
            .Select(p => new MapPoint(p.Ip, p.Latitude!.Value, p.Longitude!.Value, p.Country, p.City,
                p.Alerts, p.Events, p.MaxSeverity.ToString()))
            .ToList();

        model.RecentAlerts = await alertsQuery
            .Include(a => a.LogFile)
            .OrderByDescending(a => a.CreatedAt)
            .ThenByDescending(a => a.Id)
            .Take(6)
            .ToListAsync(ct);

        return model;
    }
}
