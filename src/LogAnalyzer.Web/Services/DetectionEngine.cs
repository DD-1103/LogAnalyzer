using System.Data;
using System.Diagnostics;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Services;

public static class UrlDecoder
{
    /// <summary>
    /// Decodes URL encoding up to two times (attackers often double-encode, e.g. %252e%252e%252f)
    /// so signatures match "' OR 1=1" as well as "%27%20OR%201%3D1".
    /// </summary>
    public static string Decode(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        var s = value.Replace('+', ' ');
        for (var i = 0; i < 2 && s.Contains('%'); i++)
        {
            var decoded = Uri.UnescapeDataString(s);
            if (decoded == s)
                break;
            s = decoded;
        }
        return s;
    }
}

/// <summary>
/// Runs all enabled detection rules over the events of one log file and stores the resulting alerts.
/// The matching itself is done by <see cref="DetectionCore"/>; this class streams events from the
/// database and writes one alert per (rule, source IP) with all matching events as evidence.
/// </summary>
public sealed class DetectionEngine(AppDbContext db, AnomalyDetector anomalyDetector, ILogger<DetectionEngine> logger)
{
    /// <summary>Alerts per rule and file; further source addresses are merged into one alert.</summary>
    public const int MaxAlertsPerRule = 1000;

    public async Task<int> RunAsync(int logFileId, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();

        var rules = await db.DetectionRules.AsNoTracking().Where(r => r.IsEnabled).ToListAsync(ct);
        var compiled = new List<CompiledRule>();
        foreach (var rule in rules.Where(r => r.Kind != RuleKind.Anomaly))
        {
            if (DetectionCore.TryCompile(rule, out var error) is { } c)
                compiled.Add(c);
            else
                logger.LogWarning("Rule {Rule} was skipped: {Error}", rule.Name, error);
        }

        // Detection is repeatable: previous results for this file are replaced.
        await LogFileCleanup.DeleteAlertsAsync(db, logFileId, ct);

        var core = new DetectionCore(compiled);
        var anomalyRules = rules.Where(r => r.Kind == RuleKind.Anomaly).ToList();
        var features = anomalyRules.Count > 0 ? new IpFeatureAccumulator() : null;
        var events = db.LogEvents.AsNoTracking()
            .Where(e => e.LogFileId == logFileId)
            .OrderBy(e => e.Timestamp).ThenBy(e => e.LineNumber)
            .Select(e => new DetectionEvent(e.Id, e.ClientIp, e.Timestamp, e.Method, e.Url, e.StatusCode,
                e.UserAgent, e.Referrer, e.ResponseSize))
            .AsAsyncEnumerable();

        await foreach (var e in events.WithCancellation(ct))
        {
            core.Process(e);
            features?.Add(e);
        }

        var findings = DetectionCore.CapPerRule(core.Hits, MaxAlertsPerRule)
            .Select(h => new DetectionFinding(h, double.NaN, "")).ToList();
        foreach (var rule in anomalyRules)
        {
            var anomalies = anomalyDetector.Detect(rule, features!);
            findings.AddRange(anomalies);
            logger.LogInformation("Anomaly rule {Rule}: {Ips} IPs profiled, {Found} anomalous",
                rule.Name, features!.Profiles.Count, anomalies.Count);
        }

        var alertCount = await SaveAlertsAsync(logFileId, rules, findings, ct);

        // Regex timeouts are reported on the file page instead of disappearing silently.
        var names = rules.ToDictionary(r => r.Id, r => r.Name);
        var warnings = core.Warnings(id => names.GetValueOrDefault(id, "#" + id));
        foreach (var w in warnings)
            logger.LogWarning("Log file {Id}: {Warning}", logFileId, w);
        var warningText = warnings.Count == 0 ? null : string.Join(" ", warnings);
        if (warningText is { Length: > 2000 })
            warningText = warningText[..2000];
        await db.LogFiles.Where(f => f.Id == logFileId)
            .ExecuteUpdateAsync(s => s.SetProperty(f => f.DetectionWarnings, warningText), ct);

        sw.Stop();
        logger.LogInformation(
            "Detection on log file {Id}: {Events:N0} events, {Rules} rules, {Alerts} alerts in {Ms} ms",
            logFileId, core.EventsProcessed, compiled.Count + anomalyRules.Count, alertCount, sw.ElapsedMilliseconds);
        return alertCount;
    }

    private static string? Describe(RuleHit hit)
    {
        var parts = new List<string>();
        if (hit.MergedSources > 0)
            parts.Add($"The rule matched more than {MaxAlertsPerRule:N0} source addresses in this file; the events of the " +
                      $"{hit.MergedSources:N0} addresses with the fewest matches are grouped in this alert.");
        if (hit.TimedOutEvents > 0)
            parts.Add($"{hit.TimedOutEvents:N0} of these events were counted because the rule's regex timed out on them (fail-closed).");
        return parts.Count == 0 ? null : string.Join(" ", parts);
    }

    private async Task<int> SaveAlertsAsync(int logFileId, List<DetectionRule> rules,
        List<DetectionFinding> hits, CancellationToken ct)
    {
        if (hits.Count == 0)
            return 0;

        var ruleById = rules.ToDictionary(r => r.Id);
        var created = new List<(Alert Alert, RuleHit Hit)>();

        foreach (var (hit, score, details) in hits)
        {
            var rule = ruleById[hit.RuleId];
            var isAnomaly = !double.IsNaN(score);
            var alert = new Alert
            {
                Title = isAnomaly ? $"Anomalous behaviour from {hit.Ip} (score {score:0.00})" : $"{rule.Name} from {hit.Ip}",
                Score = isAnomaly ? Math.Round(score, 4) : null,
                Details = isAnomaly ? details : Describe(hit),
                RuleId = rule.Id,
                LogFileId = logFileId,
                SourceIp = hit.Ip,
                AttackType = rule.AttackType,
                Severity = rule.Severity,
                Status = AlertStatus.New,
                FirstSeen = hit.First,
                LastSeen = hit.Last,
                EventCount = hit.EventIds.Count
            };
            db.Alerts.Add(alert);
            created.Add((alert, hit));
        }
        await db.SaveChangesAsync(ct);

        // Evidence can be large (one row per matching event), so it is bulk-inserted.
        var table = new DataTable();
        table.Columns.Add("AlertId", typeof(long));
        table.Columns.Add("LogEventId", typeof(long));
        foreach (var (alert, hit) in created)
            foreach (var id in hit.EventIds)
                table.Rows.Add(alert.Id, id);

        using var bulk = new SqlBulkCopy(db.Database.GetConnectionString())
        {
            DestinationTableName = "AlertEvidence",
            BatchSize = 5000,
            BulkCopyTimeout = 0
        };
        bulk.ColumnMappings.Add("AlertId", "AlertId");
        bulk.ColumnMappings.Add("LogEventId", "LogEventId");
        await bulk.WriteToServerAsync(table, ct);

        db.ChangeTracker.Clear();
        return created.Count;
    }
}
