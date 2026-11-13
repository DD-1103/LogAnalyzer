using System.Text.RegularExpressions;
using LogAnalyzer.Web.Models;

namespace LogAnalyzer.Web.Services;

/// <summary>The fields of a log event that detection looks at (no database types, so it is unit-testable).</summary>
public sealed record DetectionEvent(
    long Id,
    string ClientIp,
    DateTimeOffset Timestamp,
    string Method,
    string Url,
    int StatusCode,
    string? UserAgent,
    string? Referrer,
    long? ResponseSize = null);

/// <summary>A rule with its regexes compiled once.</summary>
public sealed class CompiledRule
{
    public required DetectionRule Rule { get; init; }
    public Regex? Pattern { get; init; }
    public Regex? PathPattern { get; init; }
    public TimeSpan Window { get; init; }
}

/// <summary>Events of one IP that matched one rule.</summary>
public sealed class RuleHit(int ruleId, string ip)
{
    public int RuleId { get; } = ruleId;
    public string Ip { get; } = ip;
    public HashSet<long> EventIds { get; } = [];
    public DateTimeOffset First { get; private set; } = DateTimeOffset.MaxValue;
    public DateTimeOffset Last { get; private set; } = DateTimeOffset.MinValue;

    /// <summary>Adds many events at once (anomaly hits cover all events of an IP).</summary>
    public void AddMany(IEnumerable<long> ids, DateTimeOffset first, DateTimeOffset last)
    {
        EventIds.UnionWith(ids);
        if (first < First) First = first;
        if (last > Last) Last = last;
    }

    public void Add(long id, DateTimeOffset ts)
    {
        if (!EventIds.Add(id))
            return;
        if (ts < First) First = ts;
        if (ts > Last) Last = ts;
    }
}

/// <summary>
/// Pure rule-matching logic shared by the detection engine, the rule tester and the unit tests.
/// Signature rules match a regex on one event; threshold rules count matching events per IP
/// inside a sliding time window. Events must be fed in timestamp order.
/// </summary>
public sealed class DetectionCore(IReadOnlyList<CompiledRule> rules)
{
    /// <summary>Limits the damage of a badly written (catastrophic backtracking) regex.</summary>
    public static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);

    private readonly Dictionary<(int RuleId, string Ip), RuleHit> _hits = [];
    private readonly Dictionary<(int RuleId, string Ip), Queue<(DateTimeOffset Ts, long Id)>> _windows = [];

    public IReadOnlyCollection<RuleHit> Hits => _hits.Values;
    public long EventsProcessed { get; private set; }

    public void Process(DetectionEvent e)
    {
        EventsProcessed++;
        var url = UrlDecoder.Decode(e.Url);

        foreach (var r in rules)
        {
            if (r.Rule.Kind == RuleKind.Signature)
            {
                var value = r.Rule.Field switch
                {
                    RuleField.UserAgent => e.UserAgent ?? string.Empty,
                    RuleField.Referrer => UrlDecoder.Decode(e.Referrer),
                    _ => url
                };
                if (r.Pattern is not null && SafeMatch(r.Pattern, value))
                    GetHit(r.Rule.Id, e.ClientIp).Add(e.Id, e.Timestamp);
            }
            else if (r.Rule.Kind == RuleKind.Threshold && MatchesThresholdFilters(r, e, url))
            {
                var key = (r.Rule.Id, e.ClientIp);
                if (!_windows.TryGetValue(key, out var window))
                    _windows[key] = window = new Queue<(DateTimeOffset, long)>();

                window.Enqueue((e.Timestamp, e.Id));
                while (e.Timestamp - window.Peek().Ts > r.Window)
                    window.Dequeue();

                // Threshold reached: every event currently in the window is evidence.
                if (window.Count >= r.Rule.Threshold)
                {
                    var hit = GetHit(r.Rule.Id, e.ClientIp);
                    foreach (var (ts, id) in window)
                        hit.Add(id, ts);
                }
            }
        }
    }

    /// <summary>Compiles a rule; returns null (with the reason) when it cannot be used.</summary>
    public static CompiledRule? TryCompile(DetectionRule rule, out string? error)
    {
        error = null;
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

            error = rule.Kind switch
            {
                RuleKind.Signature when compiled.Pattern is null => "A signature rule needs a pattern.",
                RuleKind.Threshold when rule.Threshold is not > 0 => "A threshold rule needs a threshold above 0.",
                RuleKind.Anomaly when rule.Threshold is not > 0 => "An anomaly rule needs a minimum request count above 0.",
                _ => null
            };
            return error is null ? compiled : null;
        }
        catch (ArgumentException ex)
        {
            error = "Invalid regular expression: " + ex.Message;
            return null;
        }
    }

    private static bool MatchesThresholdFilters(CompiledRule r, DetectionEvent e, string decodedUrl) =>
        (r.Rule.MethodFilter is null || string.Equals(r.Rule.MethodFilter, e.Method, StringComparison.OrdinalIgnoreCase))
        && (r.Rule.StatusFilter is null || r.Rule.StatusFilter == e.StatusCode)
        && (r.PathPattern is null || SafeMatch(r.PathPattern, decodedUrl));

    public static bool SafeMatch(Regex regex, string input)
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

    private RuleHit GetHit(int ruleId, string ip)
    {
        if (!_hits.TryGetValue((ruleId, ip), out var hit))
            _hits[(ruleId, ip)] = hit = new RuleHit(ruleId, ip);
        return hit;
    }
}
