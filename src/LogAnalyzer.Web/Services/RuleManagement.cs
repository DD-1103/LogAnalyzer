using System.Diagnostics;
using System.Text.RegularExpressions;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Services;

/// <summary>Checks a rule written by an admin before it is saved.</summary>
public static class RuleValidator
{
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromMilliseconds(100);

    // Inputs that make badly written patterns (nested quantifiers like (a+)+ ) backtrack for a very long time.
    private static readonly string[] ReDoSProbes =
    [
        new string('a', 30_000) + "!",
        string.Concat(Enumerable.Repeat("%27", 5_000)) + "\u0000",
        new string('/', 30_000) + "\u0000",
        "<" + new string(' ', 30_000) + "\u0000",
        string.Concat(Enumerable.Repeat("a=1&", 5_000)) + "\u0000",
        new string('1', 30_000) + "x",
        "<" + new string('a', 40) + "!",
        string.Concat(Enumerable.Repeat("a ", 5_000)) + "!",
        new string('<', 30_000)
    ];

    public static List<string> Validate(DetectionRule rule)
    {
        var errors = new List<string>();

        if (DetectionCore.TryCompile(rule, out var error) is null)
            errors.Add(error ?? "The rule is incomplete.");

        CheckBacktracking(rule.Pattern, "Pattern", errors);
        CheckBacktracking(rule.PathPattern, "Path pattern", errors);

        if (!Enum.IsDefined(rule.Kind))
            errors.Add("Choose a rule kind.");
        if (!Enum.IsDefined(rule.AppliesTo))
            errors.Add("Choose the kind of log the rule applies to.");
        if (!Enum.IsDefined(rule.Field))
            errors.Add("Choose a field.");

        if (rule.Kind == RuleKind.Threshold && rule.WindowSeconds is not > 0)
            errors.Add("A threshold rule needs a time window in seconds.");
        if (rule.Kind == RuleKind.DistinctCount && rule.WindowSeconds is not > 0)
            errors.Add("A distinct-count rule needs a time window in seconds.");
        if (rule.Kind == RuleKind.Anomaly && rule.ScoreThreshold is not (>= 0.5 and <= 1.0))
            errors.Add("An anomaly rule needs a score threshold between 0.5 and 1.0.");

        var firewall = rule.AppliesTo == LogSource.Firewall;
        if (UsesField(rule))
        {
            if (firewall && !FirewallFields.Contains(rule.Field))
                errors.Add("A firewall rule can inspect the message, threat name, firewall rule name, event type, " +
                           "destination port or destination IP.");
            else if (!firewall && !WebFields.Contains(rule.Field))
                errors.Add("A web rule can inspect the URL, the user agent or the referrer.");
        }
        if (firewall && rule is { Kind: RuleKind.DistinctCount, Field: RuleField.DestinationPort, Threshold: int needed }
            && PortSet.TryParse(rule.PortFilter, out var ports, out _) && ports is not null && ports.Count < needed)
            errors.Add($"The port filter lists {ports.Count} port(s), so {needed} different destination ports can never be reached.");
        if (!firewall && (!string.IsNullOrWhiteSpace(rule.ActionFilter) || !string.IsNullOrWhiteSpace(rule.PortFilter)))
            errors.Add("Action and port filters only apply to firewall rules.");
        if (firewall && (rule.MethodFilter is not null || rule.StatusFilter is not null))
            errors.Add("HTTP method and status filters only apply to web rules.");

        return errors.Distinct().ToList();
    }

    /// <summary>Fields a web access log event has.</summary>
    public static readonly IReadOnlySet<RuleField> WebFields =
        new HashSet<RuleField> { RuleField.Url, RuleField.UserAgent, RuleField.Referrer };

    /// <summary>Fields a firewall event has (the message is stored in the URL column, so it is offered as Message).</summary>
    public static readonly IReadOnlySet<RuleField> FirewallFields = new HashSet<RuleField>
    {
        RuleField.Message, RuleField.ThreatName, RuleField.RuleName, RuleField.EventType,
        RuleField.DestinationPort, RuleField.DestinationIp
    };

    /// <summary>
    /// True when the rule reads <see cref="DetectionRule.Field"/>: signature and distinct-count rules always,
    /// firewall threshold rules when they have a pattern (the pattern is matched on that field).
    /// </summary>
    public static bool UsesField(DetectionRule rule) => rule.Kind switch
    {
        RuleKind.Signature or RuleKind.DistinctCount => true,
        RuleKind.Threshold => rule.AppliesTo == LogSource.Firewall && !string.IsNullOrWhiteSpace(rule.Pattern),
        _ => false
    };

    /// <summary>
    /// Rejects patterns that are too slow on adversarial input (ReDoS). The engine also has a 250 ms timeout
    /// per match, but a slow rule would still make every log file take far longer to analyse.
    /// </summary>
    private static void CheckBacktracking(string? pattern, string label, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(pattern))
            return;
        Regex regex;
        try
        {
            // Patterns the linear-time engine supports cannot backtrack catastrophically: nothing to probe.
            if (DetectionCore.Build(pattern, out var backtracking) is not null && !backtracking)
                return;
            regex = new Regex(pattern, RegexOptions.CultureInvariant, ProbeTimeout);
        }
        catch (ArgumentException)
        {
            return; // reported by TryCompile
        }

        foreach (var probe in ReDoSProbes)
        {
            try
            {
                regex.IsMatch(probe);
            }
            catch (RegexMatchTimeoutException)
            {
                errors.Add($"{label} is too slow on long input (catastrophic backtracking). It uses a construct the " +
                           "linear-time engine does not support (backreference, lookaround or atomic group) - remove it or simplify the pattern.");
                return;
            }
        }
    }
}

public sealed class RuleTestResult
{
    public long EventsScanned { get; set; }
    public bool Truncated { get; set; }
    public int MatchedEvents { get; set; }
    public int AlertsWouldBeCreated { get; set; }
    public long DurationMs { get; set; }
    public List<(string Ip, int Events)> TopIps { get; set; } = [];
    public List<LogEvent> Samples { get; set; } = [];
    public List<string> Errors { get; set; } = [];
    public List<string> Warnings { get; set; } = [];
}

/// <summary>Runs one (possibly unsaved) rule over a stored log file without creating alerts.</summary>
public sealed class RuleTester(AppDbContext db, AnomalyDetector anomaly)
{
    public const int MaxEvents = 500_000;
    private const int MaxSamples = 25;

    public async Task<RuleTestResult> TestAsync(DetectionRule rule, int logFileId, CancellationToken ct)
    {
        var result = new RuleTestResult { Errors = RuleValidator.Validate(rule) };
        if (result.Errors.Count > 0)
            return result;

        // Web rules only run on access logs and firewall rules only on firewall logs (as in DetectionEngine).
        var source = await db.LogFiles.AsNoTracking().Where(f => f.Id == logFileId)
            .Select(f => (LogSource?)f.Source).FirstOrDefaultAsync(ct);
        if (source is null)
        {
            result.Errors.Add("The chosen log file does not exist any more.");
            return result;
        }
        if (source != rule.AppliesTo)
        {
            result.Errors.Add(rule.AppliesTo == LogSource.Firewall
                ? "This rule runs on firewall logs: choose a firewall log file to test it."
                : "This rule runs on web access logs: choose a web access log file to test it.");
            return result;
        }

        var sw = Stopwatch.StartNew();
        var testRule = Clone(rule);
        var events = db.LogEvents.AsNoTracking()
            .Where(e => e.LogFileId == logFileId)
            .OrderBy(e => e.Timestamp).ThenBy(e => e.LineNumber)
            .Take(MaxEvents)
            .Select(e => new DetectionEvent(e.Id, e.ClientIp, e.Timestamp, e.Method, e.Url, e.StatusCode,
                e.UserAgent, e.Referrer, e.ResponseSize)
            {
                DestinationIp = e.DestinationIp,
                SourcePort = e.SourcePort,
                DestinationPort = e.DestinationPort,
                Transport = e.Transport,
                Action = e.Action,
                EventType = e.EventType,
                RuleName = e.RuleName,
                ThreatName = e.ThreatName
            })
            .AsAsyncEnumerable();

        IReadOnlyCollection<RuleHit> hits;
        if (testRule.Kind == RuleKind.Anomaly)
        {
            var features = new IpFeatureAccumulator();
            await foreach (var e in events.WithCancellation(ct))
            {
                features.Add(e);
                result.EventsScanned++;
            }
            hits = anomaly.Detect(testRule, features).Select(a => a.Hit).ToList();
        }
        else
        {
            var core = new DetectionCore([DetectionCore.TryCompile(testRule, out _)!]);
            await foreach (var e in events.WithCancellation(ct))
                core.Process(e);
            result.EventsScanned = core.EventsProcessed;
            result.Warnings = core.Warnings(_ => testRule.Name);
            hits = core.Hits;
        }
        sw.Stop();

        result.Truncated = result.EventsScanned >= MaxEvents;
        result.DurationMs = sw.ElapsedMilliseconds;
        // Like DetectionEngine: at most MaxAlertsPerRule alerts plus one for all other sources (anomaly rules: no limit).
        result.AlertsWouldBeCreated = testRule.Kind == RuleKind.Anomaly
            ? hits.Count
            : Math.Min(hits.Count, DetectionEngine.MaxAlertsPerRule + 1);
        result.MatchedEvents = hits.SelectMany(h => h.EventIds).Distinct().Count();
        result.TopIps = hits.OrderByDescending(h => h.EventIds.Count).Take(10)
            .Select(h => (h.Ip, h.EventIds.Count)).ToList();

        var sampleIds = hits.SelectMany(h => h.EventIds).Distinct().Take(MaxSamples).ToList();
        result.Samples = await db.LogEvents.AsNoTracking()
            .Where(e => sampleIds.Contains(e.Id))
            .OrderBy(e => e.LineNumber)
            .ToListAsync(ct);
        return result;
    }

    private static DetectionRule Clone(DetectionRule r) => new()
    {
        Id = r.Id == 0 ? -1 : r.Id,
        Name = r.Name,
        AttackType = r.AttackType,
        Severity = r.Severity,
        Kind = r.Kind,
        Field = r.Field,
        Pattern = r.Pattern,
        Threshold = r.Threshold,
        WindowSeconds = r.WindowSeconds,
        MethodFilter = r.MethodFilter,
        PathPattern = r.PathPattern,
        StatusFilter = r.StatusFilter,
        ScoreThreshold = r.ScoreThreshold,
        AppliesTo = r.AppliesTo,
        ActionFilter = r.ActionFilter,
        PortFilter = r.PortFilter,
        IsEnabled = true
    };
}
