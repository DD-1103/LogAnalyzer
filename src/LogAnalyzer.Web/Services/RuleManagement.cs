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
        new string('1', 30_000) + "x"
    ];

    public static List<string> Validate(DetectionRule rule)
    {
        var errors = new List<string>();

        if (DetectionCore.TryCompile(rule, out var error) is null)
            errors.Add(error ?? "The rule is incomplete.");

        CheckBacktracking(rule.Pattern, "Pattern", errors);
        CheckBacktracking(rule.PathPattern, "Path pattern", errors);

        if (rule.Kind == RuleKind.Threshold && rule.WindowSeconds is not > 0)
            errors.Add("A threshold rule needs a time window in seconds.");
        if (rule.Kind == RuleKind.Anomaly && rule.ScoreThreshold is not (>= 0.5 and <= 1.0))
            errors.Add("An anomaly rule needs a score threshold between 0.5 and 1.0.");

        return errors.Distinct().ToList();
    }

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
                errors.Add($"{label} is too slow on long input (possible catastrophic backtracking, e.g. nested quantifiers like (a+)+). Simplify it.");
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

        var sw = Stopwatch.StartNew();
        var testRule = Clone(rule);
        var events = db.LogEvents.AsNoTracking()
            .Where(e => e.LogFileId == logFileId)
            .OrderBy(e => e.Timestamp).ThenBy(e => e.LineNumber)
            .Take(MaxEvents)
            .Select(e => new DetectionEvent(e.Id, e.ClientIp, e.Timestamp, e.Method, e.Url, e.StatusCode,
                e.UserAgent, e.Referrer, e.ResponseSize))
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
            hits = core.Hits;
        }
        sw.Stop();

        result.Truncated = result.EventsScanned >= MaxEvents;
        result.DurationMs = sw.ElapsedMilliseconds;
        result.AlertsWouldBeCreated = hits.Count;
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
        IsEnabled = true
    };
}
