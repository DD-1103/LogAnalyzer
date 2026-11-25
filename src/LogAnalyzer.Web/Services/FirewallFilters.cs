using System.Globalization;
using LogAnalyzer.Web.Models;

namespace LogAnalyzer.Web.Services;

/// <summary>
/// Destination-port filter of a firewall rule, parsed from text like "22, 23,3389,5900-5902".
/// Lookups are O(1) (a 65,536-bit set), so a rule with many ports costs the same as one with a single port.
/// </summary>
public sealed class PortSet
{
    /// <summary>Most ports / ranges one filter may list (keeps the text readable and the column small).</summary>
    public const int MaxEntries = 200;

    private readonly ulong[] _bits = new ulong[65536 / 64];
    private readonly List<string> _entries = [];

    private PortSet() { }

    /// <summary>Number of different ports in the set.</summary>
    public int Count => _bits.Sum(b => System.Numerics.BitOperations.PopCount(b));

    /// <summary>The entries as written (trimmed), e.g. ["22", "5900-5902"].</summary>
    public IReadOnlyList<string> Entries => _entries;

    public bool Contains(int port) =>
        port is >= 0 and <= 65535 && (_bits[port >> 6] & (1UL << (port & 63))) != 0;

    /// <summary>An event without a destination port never matches a port filter.</summary>
    public bool Contains(int? port) => port is int p && Contains(p);

    /// <summary>Canonical text: entries joined by commas without spaces.</summary>
    public override string ToString() => string.Join(",", _entries);

    /// <summary>
    /// Parses a port filter. Blank text means "any port" (returns true with <paramref name="set"/> = null).
    /// Empty entries (e.g. a trailing comma) are ignored.
    /// </summary>
    public static bool TryParse(string? text, out PortSet? set, out string? error)
    {
        set = null;
        error = null;
        if (string.IsNullOrWhiteSpace(text))
            return true;

        var result = new PortSet();
        foreach (var raw in text.Split(','))
        {
            var entry = raw.Trim();
            if (entry.Length == 0)
                continue;
            if (result._entries.Count == MaxEntries)
            {
                error = $"Port filter: at most {MaxEntries} ports or ranges.";
                return false;
            }

            var dash = entry.IndexOf('-');
            int from, to;
            if (dash < 0)
            {
                if (!TryPort(entry, out from))
                {
                    error = $"Port filter: '{Shorten(entry)}' is not a port (use numbers 0-65535 or ranges like 5900-5902).";
                    return false;
                }
                to = from;
                result._entries.Add(from.ToString(CultureInfo.InvariantCulture));
            }
            else
            {
                var a = entry[..dash].Trim();
                var b = entry[(dash + 1)..].Trim();
                if (!TryPort(a, out from) || !TryPort(b, out to))
                {
                    error = $"Port filter: '{Shorten(entry)}' is not a port range (use numbers 0-65535, e.g. 5900-5902).";
                    return false;
                }
                if (from > to)
                {
                    error = $"Port filter: '{Shorten(entry)}' is not a valid range (the first port must not be larger than the second).";
                    return false;
                }
                result._entries.Add(from == to
                    ? from.ToString(CultureInfo.InvariantCulture)
                    : $"{from.ToString(CultureInfo.InvariantCulture)}-{to.ToString(CultureInfo.InvariantCulture)}");
            }

            for (var p = from; p <= to; p++)
                result._bits[p >> 6] |= 1UL << (p & 63);
        }

        if (result._entries.Count == 0)
            return true; // only separators: same as blank
        set = result;
        return true;
    }

    private static bool TryPort(string s, out int port) =>
        int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port <= 65535;

    private static string Shorten(string s) => s.Length <= 40 ? s : s[..40] + "…";
}

/// <summary>Firewall-action filter of a rule, parsed from text like "Deny,Drop,Reject" (names are case-insensitive).</summary>
public sealed class ActionSet
{
    private readonly int _mask;

    private ActionSet(int mask, List<FirewallAction> actions)
    {
        _mask = mask;
        Actions = actions;
    }

    /// <summary>The actions in enum order, without duplicates.</summary>
    public IReadOnlyList<FirewallAction> Actions { get; }

    /// <summary>An event without an action counts as <see cref="FirewallAction.Unknown"/>.</summary>
    public bool Contains(FirewallAction? action) => (_mask & (1 << (int)(action ?? FirewallAction.Unknown))) != 0;

    /// <summary>Canonical text, e.g. "Deny,Drop,Reject".</summary>
    public override string ToString() => string.Join(",", Actions);

    /// <summary>All action names an admin may use.</summary>
    public static string AllowedNames => string.Join(", ", Enum.GetNames<FirewallAction>());

    /// <summary>Parses an action filter. Blank text means "any action" (returns true with <paramref name="set"/> = null).</summary>
    public static bool TryParse(string? text, out ActionSet? set, out string? error)
    {
        set = null;
        error = null;
        if (string.IsNullOrWhiteSpace(text))
            return true;

        var mask = 0;
        foreach (var raw in text.Split(','))
        {
            var token = raw.Trim();
            if (token.Length == 0)
                continue;
            // Names only: Enum.TryParse would also accept numbers ("2") and combinations.
            if (!token.All(char.IsAsciiLetter) || !Enum.TryParse<FirewallAction>(token, ignoreCase: true, out var action)
                || !Enum.IsDefined(action))
            {
                var shown = token.Length <= 40 ? token : token[..40] + "…";
                error = $"Action filter: '{shown}' is not a firewall action ({AllowedNames}).";
                return false;
            }
            mask |= 1 << (int)action;
        }

        if (mask == 0)
            return true;
        var actions = Enum.GetValues<FirewallAction>().Where(a => (mask & (1 << (int)a)) != 0).ToList();
        set = new ActionSet(mask, actions);
        return true;
    }
}

/// <summary>
/// What a firewall rule counts. The meaning follows from the rule's kind, field and attack type, so it needs no extra
/// settings; the rules page shows it as chips and the rule form explains it.
/// </summary>
public static class FirewallSemantics
{
    /// <summary>
    /// Counted per (source, target host): a port scan is many ports of ONE host and password guessing hits ONE host.
    /// Counting over all targets would flag NAT gateways, proxies, peer-to-peer clients (one port per server) and
    /// monitoring, backup or deployment hosts (one SSH session per server).
    /// </summary>
    public static bool CountsPerTarget(DetectionRule rule) => rule.AppliesTo == LogSource.Firewall
        && (rule is { Kind: RuleKind.DistinctCount, Field: RuleField.DestinationPort } || CountsConnections(rule));

    /// <summary>
    /// Brute-force rules count connections (different client ports), not lines: firewalls log retransmitted SYNs
    /// and the start and end of one session as separate lines.
    /// </summary>
    public static bool CountsConnections(DetectionRule rule) => rule.AppliesTo == LogSource.Firewall
        && rule is { Kind: RuleKind.Threshold, AttackType: AttackType.BruteForce };

    /// <summary>
    /// "Suspicious outbound" is about inside hosts: only private (internal) source addresses count. An internet host
    /// that probes port 4444 is background noise, not an outbound connection. For other sources (inside hosts with
    /// public addresses, inbound bind shells) use a rule with another attack type.
    /// </summary>
    public static bool InternalSourceOnly(DetectionRule rule) => rule.AppliesTo == LogSource.Firewall
        && rule.AttackType == AttackType.SuspiciousOutbound;

    /// <summary>
    /// Rules about contacted ports or hosts skip replies: the destination port of a reply is the client's temporary
    /// port (any number, also 4444 or 9001) and its destination is a client, not a target.
    /// </summary>
    public static bool IgnoresReplies(DetectionRule rule) => rule.AppliesTo == LogSource.Firewall
        && ((rule.Kind == RuleKind.DistinctCount && rule.Field is RuleField.DestinationPort or RuleField.DestinationIp)
            || (rule.Kind is RuleKind.Threshold or RuleKind.DistinctCount && !string.IsNullOrWhiteSpace(rule.PortFilter)));
}

/// <summary>
/// Address ranges organisations use inside their network. Unlike <see cref="IpAddressPolicy"/> (what may be sent to
/// providers), documentation and other reserved ranges do not count as internal.
/// </summary>
public static class InternalAddress
{
    private static readonly System.Net.IPNetwork[] Networks =
    [
        System.Net.IPNetwork.Parse("10.0.0.0/8"),
        System.Net.IPNetwork.Parse("172.16.0.0/12"),
        System.Net.IPNetwork.Parse("192.168.0.0/16"),
        System.Net.IPNetwork.Parse("100.64.0.0/10"),  // shared address space (carrier-grade NAT, overlay VPNs)
        System.Net.IPNetwork.Parse("169.254.0.0/16"), // link-local
        System.Net.IPNetwork.Parse("fc00::/7"),       // unique local
        System.Net.IPNetwork.Parse("fe80::/10")       // link-local
    ];

    public static bool IsInternal(string? ip)
    {
        if (string.IsNullOrEmpty(ip) || !System.Net.IPAddress.TryParse(ip, out var address))
            return false;
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        foreach (var network in Networks)
            if (network.Contains(address))
                return true;
        return false;
    }
}

/// <summary>Counts what the evidence of a firewall alert consists of; gives the alert a short factual explanation.</summary>
public sealed class TrafficSummary
{
    /// <summary>Different hosts / ports remembered per alert (bounds the memory of huge scans).</summary>
    public const int MaxTracked = 1000;
    private const int MaxThreats = 3;

    private readonly HashSet<string> _hosts = new(StringComparer.Ordinal);
    private readonly HashSet<int> _ports = [];
    private readonly List<string> _threats = [];
    private bool _moreHosts, _morePorts, _moreThreats;
    private int _events, _allowed, _blocked, _alerted;

    public void Add(string? destinationIp, int? destinationPort, FirewallAction? action, string? threat)
    {
        _events++;
        switch (action)
        {
            case FirewallAction.Allow: _allowed++; break;
            case FirewallAction.Deny or FirewallAction.Drop or FirewallAction.Reject: _blocked++; break;
            case FirewallAction.Alert: _alerted++; break;
        }
        if (destinationIp is not null && !_hosts.Contains(destinationIp))
        {
            if (_hosts.Count < MaxTracked) _hosts.Add(destinationIp);
            else _moreHosts = true;
        }
        if (destinationPort is int port && !_ports.Contains(port))
        {
            if (_ports.Count < MaxTracked) _ports.Add(port);
            else _morePorts = true;
        }
        if (threat is not null && !_threats.Contains(threat))
        {
            if (_threats.Count < MaxThreats) _threats.Add(threat);
            else _moreThreats = true;
        }
    }

    /// <summary>
    /// E.g. "24 events between 2026-11-21 10:10:00 and 10:10:46: 24 different destination ports (20-43) on 1 host
    /// (10.0.0.5); 24 blocked."
    /// </summary>
    public string Describe(DateTimeOffset first, DateTimeOffset last)
    {
        var inv = CultureInfo.InvariantCulture;
        string N(int n) => n.ToString("N0", inv);
        string AtLeast(int n, bool more) => more ? "more than " + N(n) : N(n);

        var from = first.ToString("yyyy-MM-dd HH:mm:ss", inv);
        var sameDay = first.Offset == last.Offset && first.Date == last.Date;
        var to = last.ToString(sameDay ? "HH:mm:ss" : "yyyy-MM-dd HH:mm:ss", inv);
        var when = first == last ? " at " + from : $" between {from} and {to}";

        var ports = _ports.Count switch
        {
            0 => null,
            1 => "destination port " + _ports.First().ToString(inv),
            _ => AtLeast(_ports.Count, _morePorts) + " different destination ports" +
                 (_morePorts ? "" : $" ({_ports.Min().ToString(inv)}-{_ports.Max().ToString(inv)})")
        };
        var hosts = _hosts.Count switch
        {
            0 => null,
            1 => $"1 host ({_hosts.First()})",
            _ => AtLeast(_hosts.Count, _moreHosts) + " different hosts"
        };
        var target = ports is not null && hosts is not null ? $"{ports} on {hosts}" : ports ?? hosts;

        var decisions = new List<string>();
        if (_allowed > 0) decisions.Add(N(_allowed) + " allowed");
        if (_blocked > 0) decisions.Add(N(_blocked) + " blocked");
        if (_alerted > 0) decisions.Add(N(_alerted) + " detected, not blocked");
        if (_events - _allowed - _blocked - _alerted is > 0 and var rest) decisions.Add(N(rest) + " without a decision");

        var text = $"{N(_events)} event{(_events == 1 ? "" : "s")}{when}{(target is null ? "" : ": " + target)}; {string.Join(", ", decisions)}.";
        if (_threats.Count > 0)
            text += " Threats: " + string.Join(", ", _threats.Select(t => t.Length <= 80 ? t : t[..80] + "...")) + (_moreThreats ? ", ..." : "") + ".";
        return text;
    }
}
