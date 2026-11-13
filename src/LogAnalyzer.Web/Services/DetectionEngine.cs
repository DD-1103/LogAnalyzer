using System.Data;
using System.Diagnostics;
using System.Text.RegularExpressions;
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
/// Signature rules match a regex on a single event; threshold rules count matching events per IP
/// inside a sliding time window. One alert is created per (rule, source IP).
/// </summary>
public sealed class DetectionEngine(AppDbContext db, ILogger<DetectionEngine> logger)
{
    // Limits the damage of a badly written (catastrophic backtracking) regex.
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);

    private sealed record EventRow(long Id, string ClientIp, DateTimeOffset Timestamp, string Method,
        string Url, int StatusCode, string? UserAgent, string? Referrer);

    private sealed class CompiledRule
    {
        public required DetectionRule Rule { get; init; }
        public Regex? Pattern { get; init; }
        public Regex? PathPattern { get; init; }
        public TimeSpan Window { get; init; }
    }

    private sealed class Hit(string ip)
    {
        public string Ip { get; } = ip;
        public HashSet<long> EventIds { get; } = [];
        public DateTimeOffset First { get; private set; } = DateTimeOffset.MaxValue;
        public DateTimeOffset Last { get; private set; } = DateTimeOffset.MinValue;

        public void Add(long id, DateTimeOffset ts)
        {
            if (!EventIds.Add(id))
                return;
            if (ts < First) First = ts;
            if (ts > Last) Last = ts;
        }
    }

    public async Task<int> RunAsync(int logFileId, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();

        var rules = await db.DetectionRules.AsNoTracking().Where(r => r.IsEnabled).ToListAsync(ct);
        var compiled = rules.Select(Compile).OfType<CompiledRule>().ToList();

        // Detection is repeatable: previous results for this file are replaced.
        await db.AlertEvidence.Where(e => e.Alert!.LogFileId == logFileId).ExecuteDeleteAsync(ct);
        await db.Alerts.Where(a => a.LogFileId == logFileId).ExecuteDeleteAsync(ct);

        var hits = new Dictionary<(int RuleId, string Ip), Hit>();
        var windows = new Dictionary<(int RuleId, string Ip), Queue<(DateTimeOffset Ts, long Id)>>();

        var events = db.LogEvents.AsNoTracking()
            .Where(e => e.LogFileId == logFileId)
            .OrderBy(e => e.Timestamp).ThenBy(e => e.LineNumber)
            .Select(e => new EventRow(e.Id, e.ClientIp, e.Timestamp, e.Method, e.Url, e.StatusCode, e.UserAgent, e.Referrer))
            .AsAsyncEnumerable();

        long scanned = 0;
        await foreach (var e in events.WithCancellation(ct))
        {
            scanned++;
            var url = UrlDecoder.Decode(e.Url);

            foreach (var r in compiled)
            {
                var key = (r.Rule.Id, e.ClientIp);

                if (r.Rule.Kind == RuleKind.Signature)
                {
                    var value = r.Rule.Field switch
                    {
                        RuleField.UserAgent => e.UserAgent ?? string.Empty,
                        RuleField.Referrer => UrlDecoder.Decode(e.Referrer),
                        _ => url
                    };
                    if (r.Pattern is not null && SafeMatch(r.Pattern, value))
                        GetHit(hits, key).Add(e.Id, e.Timestamp);
                }
                else if (MatchesThresholdFilters(r, e, url))
                {
                    if (!windows.TryGetValue(key, out var window))
                        windows[key] = window = new Queue<(DateTimeOffset, long)>();

                    window.Enqueue((e.Timestamp, e.Id));
                    while (e.Timestamp - window.Peek().Ts > r.Window)
                        window.Dequeue();

                    // Threshold reached: every event currently in the window is evidence.
                    if (window.Count >= r.Rule.Threshold)
                    {
                        var hit = GetHit(hits, key);
                        foreach (var (ts, id) in window)
                            hit.Add(id, ts);
                    }
                }
            }
        }

        var alertCount = await SaveAlertsAsync(logFileId, rules, hits, ct);

        sw.Stop();
        logger.LogInformation(
            "Detection on log file {Id}: {Events:N0} events, {Rules} rules, {Alerts} alerts in {Ms} ms",
            logFileId, scanned, compiled.Count, alertCount, sw.ElapsedMilliseconds);
        return alertCount;
    }

    private async Task<int> SaveAlertsAsync(int logFileId, List<DetectionRule> rules,
        Dictionary<(int RuleId, string Ip), Hit> hits, CancellationToken ct)
    {
        if (hits.Count == 0)
            return 0;

        var ruleById = rules.ToDictionary(r => r.Id);
        var created = new List<(Alert Alert, Hit Hit)>();

        foreach (var ((ruleId, ip), hit) in hits)
        {
            var rule = ruleById[ruleId];
            var alert = new Alert
            {
                Title = $"{rule.Name} from {ip}",
                RuleId = rule.Id,
                LogFileId = logFileId,
                SourceIp = ip,
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

    private CompiledRule? Compile(DetectionRule rule)
    {
        try
        {
            const RegexOptions options = RegexOptions.Compiled | RegexOptions.CultureInvariant;
            var compiled = new CompiledRule
            {
                Rule = rule,
                Pattern = string.IsNullOrWhiteSpace(rule.Pattern) ? null : new Regex(rule.Pattern, options, RegexTimeout),
                PathPattern = string.IsNullOrWhiteSpace(rule.PathPattern) ? null : new Regex(rule.PathPattern, options, RegexTimeout),
                Window = TimeSpan.FromSeconds(rule.WindowSeconds ?? 60)
            };

            var usable = rule.Kind == RuleKind.Signature
                ? compiled.Pattern is not null
                : rule.Threshold is > 0;
            if (!usable)
            {
                logger.LogWarning("Rule {Rule} is incomplete and was skipped", rule.Name);
                return null;
            }
            return compiled;
        }
        catch (ArgumentException ex)
        {
            logger.LogWarning(ex, "Rule {Rule} has an invalid regex and was skipped", rule.Name);
            return null;
        }
    }

    private static bool MatchesThresholdFilters(CompiledRule r, EventRow e, string decodedUrl) =>
        (r.Rule.MethodFilter is null || string.Equals(r.Rule.MethodFilter, e.Method, StringComparison.OrdinalIgnoreCase))
        && (r.Rule.StatusFilter is null || r.Rule.StatusFilter == e.StatusCode)
        && (r.PathPattern is null || SafeMatch(r.PathPattern, decodedUrl));

    private static bool SafeMatch(Regex regex, string input)
    {
        try
        {
            return regex.IsMatch(input);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    private static Hit GetHit(Dictionary<(int, string), Hit> hits, (int, string Ip) key)
    {
        if (!hits.TryGetValue(key, out var hit))
            hits[key] = hit = new Hit(key.Ip);
        return hit;
    }
}
