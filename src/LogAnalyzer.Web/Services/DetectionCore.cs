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
    long? ResponseSize = null)
{
    // Firewall fields (null for web access logs); for firewall events Url holds the message.
    public string? DestinationIp { get; init; }
    public int? SourcePort { get; init; }
    public int? DestinationPort { get; init; }
    public string? Transport { get; init; }
    public FirewallAction? Action { get; init; }
    public string? EventType { get; init; }
    public string? RuleName { get; init; }
    public string? ThreatName { get; init; }
}

/// <summary>A rule with its regexes compiled once.</summary>
public sealed class CompiledRule
{
    public required DetectionRule Rule { get; init; }
    public Regex? Pattern { get; init; }
    public Regex? PathPattern { get; init; }
    public TimeSpan Window { get; init; }

    /// <summary>Destination-port filter (firewall rules only; null = any port).</summary>
    public PortSet? Ports { get; init; }

    /// <summary>Firewall-action filter (firewall rules only; null = any action).</summary>
    public ActionSet? Actions { get; init; }

    public bool IsFirewall => Rule.AppliesTo == LogSource.Firewall;

    /// <summary>
    /// True when a pattern needs the backtracking engine (backreferences, lookarounds, atomic groups):
    /// only such rules can time out. All other rules use the linear-time NonBacktracking engine.
    /// </summary>
    public bool Backtracking { get; init; }
}

/// <summary>Outcome of one regex evaluation. A timeout is never treated as a silent "no match".</summary>
public enum MatchOutcome
{
    NoMatch,
    Match,
    Timeout
}

/// <summary>Events of one IP that matched one rule.</summary>
public sealed class RuleHit(int ruleId, string ip)
{
    public int RuleId { get; } = ruleId;
    public string Ip { get; } = ip;
    public HashSet<long> EventIds { get; } = [];

    /// <summary>Events counted as matches only because the rule's regex timed out (fail-closed).</summary>
    public int TimedOutEvents { get; set; }

    /// <summary>Above 0: this hit merges the evidence of that many source addresses (see <see cref="DetectionCore.CapPerRule"/>).</summary>
    public int MergedSources { get; set; }
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
/// inside a sliding time window; distinct-count rules (firewall) count the different values of a field
/// (destination ports = port scan, destination IPs = network sweep) per source IP inside the window.
/// Events must be fed in timestamp order.
/// </summary>
public sealed class DetectionCore(IReadOnlyList<CompiledRule> rules)
{
    /// <summary>Limits the damage of a badly written (catastrophic backtracking) regex.</summary>
    public static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);

    /// <summary>After this many timeouts in one file a rule is skipped for the rest of it (circuit breaker).</summary>
    public const int MaxTimeoutsPerRule = 50;

    private readonly Dictionary<(int RuleId, string Ip), RuleHit> _hits = [];
    private readonly Dictionary<int, int> _timeouts = [];
    private readonly Dictionary<int, long> _skipped = [];
    private readonly Dictionary<(int RuleId, string Ip), SlidingWindow> _windows = [];
    private readonly Dictionary<(int RuleId, string Ip), DistinctWindow> _distinctWindows = [];

    public IReadOnlyCollection<RuleHit> Hits => _hits.Values;
    public long EventsProcessed { get; private set; }

    /// <summary>Regex timeouts per rule id (each one was counted as a match).</summary>
    public IReadOnlyDictionary<int, int> Timeouts => _timeouts;

    /// <summary>Events per rule id that were not checked because the rule's circuit breaker was open.</summary>
    public IReadOnlyDictionary<int, long> SkippedEvents => _skipped;

    /// <summary>Human-readable notes about timeouts and skipped rules (shown on the file page / rule tester).</summary>
    public List<string> Warnings(Func<int, string> ruleName)
    {
        var list = new List<string>();
        foreach (var (ruleId, count) in _timeouts)
        {
            var text = $"Rule \"{ruleName(ruleId)}\" timed out on {count:N0} event(s); they were counted as matches.";
            if (_skipped.TryGetValue(ruleId, out var skipped))
                text += $" After {MaxTimeoutsPerRule} timeouts the rule was skipped for the remaining {skipped:N0} event(s).";
            list.Add(text + " Simplify its pattern.");
        }
        return list;
    }

    public void Process(DetectionEvent e)
    {
        EventsProcessed++;
        string? decodedUrl = null; // decoded only when a web rule needs it

        foreach (var r in rules)
        {
            if (r.IsFirewall)
            {
                ProcessFirewall(r, e);
                continue;
            }

            var url = decodedUrl ??= UrlDecoder.Decode(e.Url);
            if (r.Rule.Kind == RuleKind.Signature)
            {
                var value = r.Rule.Field switch
                {
                    RuleField.UserAgent => e.UserAgent ?? string.Empty,
                    RuleField.Referrer => UrlDecoder.Decode(e.Referrer),
                    RuleField.Url => url,
                    var other => FieldValue(other, e) // firewall fields: null on web events = no match
                };
                var outcome = r.Pattern is null || value is null ? MatchOutcome.NoMatch : Evaluate(r, r.Pattern, value);
                if (outcome != MatchOutcome.NoMatch)
                {
                    var hit = GetHit(r.Rule.Id, e.ClientIp);
                    hit.Add(e.Id, e.Timestamp);
                    if (outcome == MatchOutcome.Timeout)
                        hit.TimedOutEvents++;
                }
            }
            else if (r.Rule.Kind == RuleKind.Threshold && MatchesThresholdFilters(r, e, url))
            {
                var key = (r.Rule.Id, e.ClientIp);
                if (!_windows.TryGetValue(key, out var window))
                    _windows[key] = window = new SlidingWindow();

                window.Add(e.Timestamp, e.Id);
                window.DropOlderThan(e.Timestamp - r.Window);

                // Threshold reached: every event currently in the window is evidence. Events added at an earlier
                // trigger are already in the hit, so only the not-yet-added newest ones are copied (linear time;
                // copying the whole window every time was quadratic for fast scanners).
                if (window.Count >= r.Rule.Threshold)
                    window.FlushPending(GetHit(r.Rule.Id, e.ClientIp));
            }
        }
    }

    /// <summary>
    /// Firewall rules: the action and port filters apply to every kind; text fields are matched as logged
    /// (no URL decoding). Threshold and distinct-count rules work per source IP; events without a source are skipped.
    /// </summary>
    private void ProcessFirewall(CompiledRule r, DetectionEvent e)
    {
        if (r.Actions is not null && !r.Actions.Contains(e.Action))
            return;
        if (r.Ports is not null && !r.Ports.Contains(e.DestinationPort))
            return;

        switch (r.Rule.Kind)
        {
            case RuleKind.Signature:
            {
                var value = FieldValue(r.Rule.Field, e);
                if (r.Pattern is null || value is null)
                    return;
                var outcome = Evaluate(r, r.Pattern, value);
                if (outcome == MatchOutcome.NoMatch)
                    return;
                var hit = GetHit(r.Rule.Id, e.ClientIp);
                hit.Add(e.Id, e.Timestamp);
                if (outcome == MatchOutcome.Timeout)
                    hit.TimedOutEvents++;
                return;
            }

            case RuleKind.Threshold:
            {
                if (!HasSource(e) || !MatchesFirewallPatterns(r, e, FieldValue(r.Rule.Field, e)))
                    return;
                var key = (r.Rule.Id, e.ClientIp);
                if (!_windows.TryGetValue(key, out var window))
                    _windows[key] = window = new SlidingWindow();
                window.Add(e.Timestamp, e.Id);
                window.DropOlderThan(e.Timestamp - r.Window);
                if (window.Count >= r.Rule.Threshold)
                    window.FlushPending(GetHit(r.Rule.Id, e.ClientIp));
                return;
            }

            case RuleKind.DistinctCount:
            {
                if (!HasSource(e))
                    return;
                var value = FieldValue(r.Rule.Field, e);
                if (value is null || !MatchesFirewallPatterns(r, e, value))
                    return;
                var key = (r.Rule.Id, e.ClientIp);
                if (!_distinctWindows.TryGetValue(key, out var window))
                    _distinctWindows[key] = window = new DistinctWindow();
                window.Add(e.Timestamp, e.Id, value);
                window.DropOlderThan(e.Timestamp - r.Window);
                // Enough different values (ports, hosts, ...) inside the window: every event in it is evidence.
                if (window.Distinct >= r.Rule.Threshold)
                    window.FlushPending(GetHit(r.Rule.Id, e.ClientIp));
                return;
            }
        }
    }

    /// <summary>"-" (or nothing) means the line had no source address: it cannot be attributed to one attacker.</summary>
    private static bool HasSource(DetectionEvent e) => !string.IsNullOrEmpty(e.ClientIp) && e.ClientIp != "-";

    /// <summary>
    /// Optional regexes of firewall threshold / distinct-count rules: the path pattern on the message, and the
    /// pattern on the rule's field (e.g. Field EventType, Pattern ^auth$). A timeout counts as a match (fail-closed).
    /// </summary>
    private bool MatchesFirewallPatterns(CompiledRule r, DetectionEvent e, string? fieldValue)
    {
        if (r.PathPattern is not null && Evaluate(r, r.PathPattern, e.Url ?? string.Empty) == MatchOutcome.NoMatch)
            return false;
        if (r.Pattern is not null && (fieldValue is null || Evaluate(r, r.Pattern, fieldValue) == MatchOutcome.NoMatch))
            return false;
        return true;
    }

    /// <summary>
    /// Raw text of a field (no URL decoding). For firewall events <see cref="DetectionEvent.Url"/> holds the message.
    /// Null when the event does not have the field.
    /// </summary>
    public static string? FieldValue(RuleField field, DetectionEvent e) => field switch
    {
        RuleField.Url or RuleField.Message => e.Url,
        RuleField.UserAgent => e.UserAgent,
        RuleField.Referrer => e.Referrer,
        RuleField.ThreatName => e.ThreatName,
        RuleField.RuleName => e.RuleName,
        RuleField.EventType => e.EventType,
        RuleField.DestinationIp => e.DestinationIp,
        RuleField.DestinationPort => e.DestinationPort is int p ? PortText(p) : null,
        _ => null
    };

    private static readonly string?[] PortTexts = new string?[65536];

    /// <summary>Port number as text, cached (a port scan produces millions of these).</summary>
    private static string PortText(int port) =>
        port is >= 0 and <= 65535
            ? PortTexts[port] ??= port.ToString(System.Globalization.CultureInfo.InvariantCulture)
            : port.ToString(System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>
    /// Keeps at most <paramref name="maxPerRule"/> alerts per rule (the sources with the most events). The evidence of
    /// all other sources is merged into one extra hit, so no matching event is lost (evaluation metrics stay exact),
    /// but a log with 200k fake or spoofed "IP" values cannot create 200k alerts.
    /// </summary>
    public static List<RuleHit> CapPerRule(IEnumerable<RuleHit> hits, int maxPerRule)
    {
        var result = new List<RuleHit>();
        foreach (var group in hits.GroupBy(h => h.RuleId))
        {
            var ordered = group.OrderByDescending(h => h.EventIds.Count).ThenBy(h => h.Ip, StringComparer.Ordinal).ToList();
            if (ordered.Count <= maxPerRule)
            {
                result.AddRange(ordered);
                continue;
            }
            result.AddRange(ordered.Take(maxPerRule));
            var rest = ordered.Skip(maxPerRule).ToList();
            var merged = new RuleHit(group.Key, $"{rest.Count:N0} other IPs") { MergedSources = rest.Count };
            foreach (var h in rest)
            {
                merged.AddMany(h.EventIds, h.First, h.Last);
                merged.TimedOutEvents += h.TimedOutEvents;
            }
            result.Add(merged);
        }
        return result;
    }

    /// <summary>Compiles a rule; returns null (with the reason) when it cannot be used.</summary>
    public static CompiledRule? TryCompile(DetectionRule rule, out string? error)
    {
        error = null;
        try
        {
            if (!PortSet.TryParse(rule.PortFilter, out var ports, out error)
                || !ActionSet.TryParse(rule.ActionFilter, out var actions, out error))
                return null;

            var pattern = Build(rule.Pattern, out var patternBacktracks);
            var path = Build(rule.PathPattern, out var pathBacktracks);
            var compiled = new CompiledRule
            {
                Rule = rule,
                Pattern = pattern,
                PathPattern = path,
                Window = TimeSpan.FromSeconds(rule.WindowSeconds ?? 60),
                Backtracking = patternBacktracks || pathBacktracks,
                Ports = ports,
                Actions = actions
            };

            error = rule.Kind switch
            {
                RuleKind.Signature when compiled.Pattern is null => "A signature rule needs a pattern.",
                RuleKind.Threshold when rule.Threshold is not > 0 => "A threshold rule needs a threshold above 0.",
                RuleKind.Anomaly when rule.Threshold is not > 0 => "An anomaly rule needs a minimum request count above 0.",
                RuleKind.Anomaly when rule.AppliesTo != LogSource.WebAccess => "Anomaly rules only run on web access logs.",
                RuleKind.DistinctCount when rule.AppliesTo != LogSource.Firewall => "Distinct-count rules only run on firewall logs.",
                RuleKind.DistinctCount when rule.Threshold is not >= 2 =>
                    "A distinct-count rule needs a threshold of at least 2 different values.",
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

    /// <summary>
    /// Compiles with the NonBacktracking engine (linear time: no catastrophic backtracking, so no timeouts and no
    /// ReDoS evasion). Patterns using constructs it does not support fall back to the classic engine with a timeout.
    /// </summary>
    public static Regex? Build(string? pattern, out bool backtracking)
    {
        backtracking = false;
        if (string.IsNullOrWhiteSpace(pattern))
            return null;
        try
        {
            return new Regex(pattern, RegexOptions.NonBacktracking | RegexOptions.CultureInvariant, RegexTimeout);
        }
        catch (NotSupportedException)
        {
            backtracking = true;
            return new Regex(pattern, RegexOptions.Compiled | RegexOptions.CultureInvariant, RegexTimeout);
        }
    }

    private bool MatchesThresholdFilters(CompiledRule r, DetectionEvent e, string decodedUrl) =>
        (r.Rule.MethodFilter is null || string.Equals(r.Rule.MethodFilter, e.Method, StringComparison.OrdinalIgnoreCase))
        && (r.Rule.StatusFilter is null || r.Rule.StatusFilter == e.StatusCode)
        && (r.PathPattern is null || Evaluate(r, r.PathPattern, decodedUrl) != MatchOutcome.NoMatch);

    /// <summary>
    /// Runs one regex of a rule. A timeout is fail-closed (counted as a match and reported), so an attacker cannot
    /// hide a payload behind input that makes a weak pattern backtrack. After <see cref="MaxTimeoutsPerRule"/>
    /// timeouts the rule is skipped for the rest of the file (reported as well) so the worker is not blocked for hours.
    /// </summary>
    private MatchOutcome Evaluate(CompiledRule r, Regex regex, string input)
    {
        var id = r.Rule.Id;
        if (_timeouts.TryGetValue(id, out var count) && count >= MaxTimeoutsPerRule)
        {
            _skipped[id] = _skipped.GetValueOrDefault(id) + 1;
            return MatchOutcome.NoMatch;
        }
        var outcome = Match(regex, input);
        if (outcome == MatchOutcome.Timeout)
            _timeouts[id] = count + 1;
        return outcome;
    }

    public static MatchOutcome Match(Regex regex, string input)
    {
        try
        {
            return regex.IsMatch(input) ? MatchOutcome.Match : MatchOutcome.NoMatch;
        }
        catch (RegexMatchTimeoutException)
        {
            return MatchOutcome.Timeout;
        }
    }

    private RuleHit GetHit(int ruleId, string ip)
    {
        if (!_hits.TryGetValue((ruleId, ip), out var hit))
            _hits[(ruleId, ip)] = hit = new RuleHit(ruleId, ip);
        return hit;
    }
}

/// <summary>
/// Events of one (threshold rule, IP) inside the time window, oldest first. <see cref="Pending"/> counts the newest
/// events that are not yet evidence; all older events in the window already are (invariant).
/// </summary>
internal sealed class SlidingWindow
{
    private readonly List<(DateTimeOffset Ts, long Id)> _items = [];
    private int _head;

    public int Count => _items.Count - _head;
    public int Pending { get; private set; }

    public void Add(DateTimeOffset ts, long id)
    {
        _items.Add((ts, id));
        Pending++;
    }

    /// <summary>Removes events older than <paramref name="cutoff"/> (the newest event always stays).</summary>
    public void DropOlderThan(DateTimeOffset cutoff)
    {
        while (Count > 1 && _items[_head].Ts < cutoff)
            _head++;
        if (Pending > Count)
            Pending = Count;
        // Reclaim memory now and then instead of shifting the list on every event.
        if (_head > 1024 && _head > _items.Count / 2)
        {
            _items.RemoveRange(0, _head);
            _head = 0;
        }
    }

    /// <summary>Adds the pending (newest) events to the hit; afterwards the whole window is evidence.</summary>
    public void FlushPending(RuleHit hit)
    {
        for (var i = _items.Count - Pending; i < _items.Count; i++)
            hit.Add(_items[i].Id, _items[i].Ts);
        Pending = 0;
    }
}

/// <summary>
/// Events of one (distinct-count rule, source IP) inside the time window, oldest first, with a value -> count map so
/// the number of DIFFERENT values (ports, hosts, ...) is known in O(1). Like <see cref="SlidingWindow"/>,
/// <see cref="Pending"/> counts the newest events that are not evidence yet, so each event is copied at most once.
/// </summary>
internal sealed class DistinctWindow
{
    private readonly List<(DateTimeOffset Ts, long Id, string Value)> _items = [];
    private readonly Dictionary<string, int> _counts = new(StringComparer.Ordinal);
    private int _head;

    public int Count => _items.Count - _head;
    public int Pending { get; private set; }

    /// <summary>Number of different values among the events in the window.</summary>
    public int Distinct => _counts.Count;

    public void Add(DateTimeOffset ts, long id, string value)
    {
        _items.Add((ts, id, value));
        _counts[value] = _counts.GetValueOrDefault(value) + 1;
        Pending++;
    }

    /// <summary>Removes events older than <paramref name="cutoff"/> (the newest event always stays).</summary>
    public void DropOlderThan(DateTimeOffset cutoff)
    {
        while (Count > 1 && _items[_head].Ts < cutoff)
        {
            var value = _items[_head].Value;
            var left = _counts[value] - 1;
            if (left == 0)
                _counts.Remove(value);
            else
                _counts[value] = left;
            _head++;
        }
        if (Pending > Count)
            Pending = Count;
        if (_head > 1024 && _head > _items.Count / 2)
        {
            _items.RemoveRange(0, _head);
            _head = 0;
        }
    }

    /// <summary>Adds the pending (newest) events to the hit; afterwards the whole window is evidence.</summary>
    public void FlushPending(RuleHit hit)
    {
        for (var i = _items.Count - Pending; i < _items.Count; i++)
            hit.Add(_items[i].Id, _items[i].Ts);
        Pending = 0;
    }
}
