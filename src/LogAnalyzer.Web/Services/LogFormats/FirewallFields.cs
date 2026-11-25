using System.Globalization;
using System.Text;
using LogAnalyzer.Web.Models;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>An address as found in a log: IP, optional port and optional interface ("1.2.3.4:51234:X1").</summary>
public readonly record struct Endpoint(string? Ip, int? Port, string? Interface);

/// <summary>Normalisation shared by the key=value, CEF, LEEF and JSON firewall formats (pure, unit-tested).</summary>
public static class FirewallFields
{
    private static readonly Dictionary<string, FirewallAction> ActionWords = BuildActions();
    private static readonly Dictionary<string, FirewallAction>.AlternateLookup<ReadOnlySpan<char>> ActionLookup =
        ActionWords.GetAlternateLookup<ReadOnlySpan<char>>();

    private static Dictionary<string, FirewallAction> BuildActions()
    {
        var d = new Dictionary<string, FirewallAction>(StringComparer.Ordinal);
        void Add(FirewallAction a, params string[] words)
        {
            foreach (var w in words)
                d[w] = a;
        }
        // Session ends of an allowed connection (FortiGate close / timeout / client-rst / server-rst) count as Allow.
        Add(FirewallAction.Allow, "accept", "accepted", "allow", "allowed", "pass", "passed", "permit", "permitted", "built",
            "close", "closed", "start", "started", "ok", "forward", "forwarded", "passthrough", "pass-session", "timeout",
            "client-rst", "server-rst", "bypass", "encrypt", "decrypt", "access-forward", "success", "teardown");
        Add(FirewallAction.Deny, "deny", "denied", "block", "blocked", "discard", "discarded", "ban", "banned", "prevent",
            "prevented", "refuse", "refused", "access-block", "quarantine", "quarantined", "blacklist", "blocklist", "deny-all");
        Add(FirewallAction.Drop, "drop", "dropped", "drop-packet", "drop-session", "silent-drop");
        Add(FirewallAction.Reject, "reject", "rejected", "reset", "reset-both", "reset-client", "reset-server", "rst",
            "clear-session", "reset-connection");
        Add(FirewallAction.Alert, "alert", "alerted", "detect", "detected", "monitor", "monitored", "log", "logged", "logonly",
            "log-only", "inform");
        return d;
    }

    /// <summary>Vendor action word to <see cref="FirewallAction"/>; null when the word is unknown.</summary>
    public static FirewallAction? TryAction(string? word)
    {
        if (string.IsNullOrWhiteSpace(word) || word.Length > 40)
            return null;
        Span<char> buffer = stackalloc char[40];
        var n = 0;
        foreach (var c in word.AsSpan().Trim())
            buffer[n++] = c is ' ' or '_' ? '-' : char.ToLowerInvariant(c);
        return ActionLookup.TryGetValue(buffer[..n], out var a) ? a : null;
    }

    public static FirewallAction Action(string? word) => TryAction(word) ?? FirewallAction.Unknown;

    private static readonly Dictionary<int, string> ProtocolNumbers = new()
    {
        [1] = "icmp", [2] = "igmp", [4] = "ipip", [6] = "tcp", [17] = "udp", [41] = "ipv6", [47] = "gre", [50] = "esp",
        [51] = "ah", [58] = "ipv6-icmp", [89] = "ospf", [103] = "pim", [112] = "vrrp", [132] = "sctp"
    };

    private static readonly HashSet<string> ProtocolNames =
        ["icmp", "igmp", "ipip", "tcp", "udp", "ipv6", "gre", "esp", "ah", "ipv6-icmp", "ospf", "pim", "vrrp", "sctp"];

    /// <summary>"6" / "TCP" / "tcp/ssh" / "tcp/ip" / "ICMPv6" to a lower-case transport name; null when not a transport.</summary>
    public static string? Transport(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        var v = value.Trim();
        var slash = v.IndexOf('/');
        if (slash > 0)
            v = v[..slash];
        if (int.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var number))
            return ProtocolNumbers.GetValueOrDefault(number);
        v = v.ToLowerInvariant();
        return v switch
        {
            "icmpv6" or "icmp6" or "ipv6icmp" => "ipv6-icmp",
            "ip-in-ip" => "ipip",
            _ => ProtocolNames.Contains(v) ? v : null
        };
    }

    public static int? Port(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        return int.TryParse(value.AsSpan().Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var p) && p <= 65535 ? p : null;
    }

    public static long? Long(string? value) =>
        !string.IsNullOrWhiteSpace(value) && long.TryParse(value.AsSpan().Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var l)
            ? l : null;

    /// <summary>Sum of sent and received bytes (null when neither is present).</summary>
    public static long? Bytes(string? sent, string? received, string? total = null)
    {
        var s = Long(sent);
        var r = Long(received);
        if (s is null && r is null)
            return Long(total);
        return (s ?? 0) + (r ?? 0);
    }

    /// <summary>True for a literal IPv4 (dotted quad) or IPv6 address (a zone id is allowed: "fe80::1%eth0").</summary>
    public static bool IsIp(ReadOnlySpan<char> value)
    {
        var zone = value.IndexOf('%');
        return ParsedLine.IsIpLiteral(zone > 0 && value[..zone].Contains(':') ? value[..zone] : value);
    }

    /// <summary>
    /// Splits "1.2.3.4", "1.2.3.4:51234", "1.2.3.4:51234:X1" (SonicWall), "[2001:db8::1]:443" and "2001:db8::1"
    /// (more than one colon without brackets = IPv6, never split). Ip is null when the value holds no address.
    /// </summary>
    public static Endpoint SplitEndpoint(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return default;
        var v = value.AsSpan().Trim();
        if (IsIp(v))
            return new Endpoint(v.ToString(), null, null);

        if (v.Length > 2 && v[0] == '[')
        {
            var close = v.IndexOf(']');
            if (close > 1 && IsIp(v[1..close]))
            {
                var rest = v[(close + 1)..];
                int? port = null;
                string? iface = null;
                if (rest.Length > 1 && rest[0] == ':')
                    (port, iface) = PortAndInterface(rest[1..]);
                return new Endpoint(v[1..close].ToString(), port, iface);
            }
            return default;
        }

        var colon = v.IndexOf(':');
        if (colon > 0 && IsIp(v[..colon]))
        {
            var (port, iface) = PortAndInterface(v[(colon + 1)..]);
            return new Endpoint(v[..colon].ToString(), port, iface);
        }
        return default;
    }

    private static (int? Port, string? Interface) PortAndInterface(ReadOnlySpan<char> rest)
    {
        var colon = rest.IndexOf(':');
        var portPart = colon < 0 ? rest : rest[..colon];
        int? port = int.TryParse(portPart, NumberStyles.None, CultureInfo.InvariantCulture, out var p) && p <= 65535 ? p : null;
        string? iface = colon >= 0 && colon + 1 < rest.Length ? rest[(colon + 1)..].ToString() : null;
        return (port, iface);
    }

    /// <summary>An IP from a value that may carry a port; null when it is not an address.</summary>
    public static string? Ip(string? value) => SplitEndpoint(value).Ip;

    /// <summary>"GUI(203.0.113.9)" / "ssh(203.0.113.9)" / "https(2001:db8::9)" to the address inside the brackets.</summary>
    public static string? IpInParentheses(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return null;
        var open = value.IndexOf('(');
        var close = open < 0 ? -1 : value.IndexOf(')', open + 1);
        return close > open + 1 ? Ip(value[(open + 1)..close]) : Ip(value);
    }

    /// <summary>Source address and port of a key=value line (aliases, "ip:port" values split).</summary>
    public static Endpoint Source(KeyValueLine kv) => EndpointOf(kv, KvField.SourceIp, KvField.SourcePort);

    public static Endpoint Destination(KeyValueLine kv) => EndpointOf(kv, KvField.DestinationIp, KvField.DestinationPort);

    private static Endpoint EndpointOf(KeyValueLine kv, KvField ipField, KvField portField)
    {
        Endpoint found = default;
        // 0.0.0.0 / :: ("no address", e.g. Zyxel system messages) count as missing.
        if (kv.GetMappedString(ipField, static v => SplitEndpoint(v).Ip is null or "0.0.0.0" or "::" ? null : v) is { } raw)
            found = SplitEndpoint(raw);
        if (found.Ip is null)
            return default;
        var port = kv.GetMapped(portField, static v => Port(v)) ?? found.Port;
        return found with { Port = port };
    }

    public static string? TransportOf(KeyValueLine kv) => kv.GetMappedString(KvField.Protocol, static v => Transport(v));

    public static FirewallAction? ActionOf(KeyValueLine kv) => kv.GetMapped(KvField.Action, static v => TryAction(v));

    /// <summary>"deny tcp 203.0.113.5:51234 -> 10.0.0.5:22 (policy Deny-All)".</summary>
    public static string Summary(FirewallAction action, string? transport, Endpoint source, Endpoint destination,
        string? rule = null, string? extra = null)
    {
        var sb = new StringBuilder(96);
        sb.Append(action == FirewallAction.Unknown ? "event" : action.ToString().ToLowerInvariant());
        if (transport is not null)
            sb.Append(' ').Append(transport);
        sb.Append(' ');
        AppendEndpoint(sb, source);
        sb.Append(" -> ");
        AppendEndpoint(sb, destination);
        if (!string.IsNullOrWhiteSpace(rule))
            sb.Append(" (policy ").Append(rule).Append(')');
        if (!string.IsNullOrWhiteSpace(extra))
            sb.Append(": ").Append(extra);
        return sb.ToString();
    }

    private static void AppendEndpoint(StringBuilder sb, Endpoint e)
    {
        if (e.Ip is null)
        {
            sb.Append('-');
            return;
        }
        var v6 = e.Ip.Contains(':');
        if (v6 && e.Port is not null)
            sb.Append('[').Append(e.Ip).Append(']');
        else
            sb.Append(e.Ip);
        if (e.Port is not null)
            sb.Append(':').Append(e.Port.Value.ToString(CultureInfo.InvariantCulture));
    }

    /// <summary>
    /// Builds the event and applies the shared acceptance rule: Parsed only with a time stamp and a source or
    /// destination address (auth events: a source address); otherwise Skipped (no address) or Failed (no time).
    /// </summary>
    public static ParseOutcome Build(out ParsedLine? result, DateTimeOffset? timestamp, FirewallAction action,
        Endpoint source, Endpoint destination, string? transport, string eventType, string? message,
        string? rule = null, string? threat = null, string? device = null, long? bytes = null)
    {
        result = null;
        var hasAddress = eventType == "auth" ? source.Ip is not null : source.Ip is not null || destination.Ip is not null;
        if (!hasAddress)
            return ParseOutcome.Skipped;
        if (timestamp is null)
            return ParseOutcome.Failed;
        var text = string.IsNullOrWhiteSpace(message) ? Summary(action, transport, source, destination, rule, threat) : message;
        result = ParsedLine.Network(source.Ip, timestamp.Value, action, Shorten(text, 1000)!, destination.Ip, source.Port,
            destination.Port, transport, eventType, Shorten(rule, 200), Shorten(threat, 300), Shorten(device, 100), bytes);
        return ParseOutcome.Parsed;
    }

    private static string? Shorten(string? v, int max) => v is null || v.Length <= max ? v : v[..max];

    public static bool ContainsIgnoreCase(string? text, string value) =>
        text is not null && text.Contains(value, StringComparison.OrdinalIgnoreCase);

    /// <summary>Login failure wording ("failed", "denied", "bad credentials", "invalid password").</summary>
    public static bool LooksLikeFailure(string? text) =>
        text is not null && (ContainsIgnoreCase(text, "fail") || ContainsIgnoreCase(text, "denied") || ContainsIgnoreCase(text, "invalid")
                             || ContainsIgnoreCase(text, "bad credential") || ContainsIgnoreCase(text, "incorrect")
                             || ContainsIgnoreCase(text, "wrong") || ContainsIgnoreCase(text, "rejected"));

    /// <summary>Words that mark an IPS / anti-malware / botnet event.</summary>
    public static bool LooksLikeThreat(string? text) =>
        text is not null && (ContainsIgnoreCase(text, "intrusion") || ContainsIgnoreCase(text, "ips") || ContainsIgnoreCase(text, "ids")
                             || ContainsIgnoreCase(text, "threat") || ContainsIgnoreCase(text, "malware") || ContainsIgnoreCase(text, "virus")
                             || ContainsIgnoreCase(text, "attack") || ContainsIgnoreCase(text, "exploit") || ContainsIgnoreCase(text, "botnet")
                             || ContainsIgnoreCase(text, "spyware") || ContainsIgnoreCase(text, "vulnerability") || ContainsIgnoreCase(text, "trojan")
                             || ContainsIgnoreCase(text, "signature") || ContainsIgnoreCase(text, "anomaly"));

    /// <summary>Words that mark a login / authentication event.</summary>
    public static bool LooksLikeAuth(string? text) =>
        text is not null && (ContainsIgnoreCase(text, "login") || ContainsIgnoreCase(text, "log in") || ContainsIgnoreCase(text, "logon")
                             || ContainsIgnoreCase(text, "authentication") || ContainsIgnoreCase(text, "auth-") || ContainsIgnoreCase(text, "_auth")
                             || ContainsIgnoreCase(text, "auth_"));
}

/// <summary>Time stamp helpers on top of <see cref="LogTime"/>: epochs of any precision, zone words and offsets.</summary>
public static class FirewallTime
{
    private static readonly Dictionary<string, TimeSpan> ZoneWords = new(StringComparer.OrdinalIgnoreCase)
    {
        ["UTC"] = TimeSpan.Zero, ["GMT"] = TimeSpan.Zero, ["Z"] = TimeSpan.Zero, ["UT"] = TimeSpan.Zero,
        ["WET"] = TimeSpan.Zero, ["WEST"] = TimeSpan.FromHours(1), ["BST"] = TimeSpan.FromHours(1),
        ["CET"] = TimeSpan.FromHours(1), ["CEST"] = TimeSpan.FromHours(2), ["MET"] = TimeSpan.FromHours(1),
        ["MEST"] = TimeSpan.FromHours(2), ["EET"] = TimeSpan.FromHours(2), ["EEST"] = TimeSpan.FromHours(3),
        ["MSK"] = TimeSpan.FromHours(3), ["EST"] = TimeSpan.FromHours(-5), ["EDT"] = TimeSpan.FromHours(-4),
        ["CST"] = TimeSpan.FromHours(-6), ["CDT"] = TimeSpan.FromHours(-5), ["MST"] = TimeSpan.FromHours(-7),
        ["MDT"] = TimeSpan.FromHours(-6), ["PST"] = TimeSpan.FromHours(-8), ["PDT"] = TimeSpan.FromHours(-7),
        ["JST"] = TimeSpan.FromHours(9)
    };

    /// <summary>"+0100", "+01:00", "-07", "UTC", "CET", "GMT+1" to an offset.</summary>
    public static bool TryOffset(string? value, out TimeSpan offset)
    {
        offset = TimeSpan.Zero;
        if (string.IsNullOrWhiteSpace(value))
            return false;
        var v = value.Trim().Trim('"');
        if (ZoneWords.TryGetValue(v, out offset))
            return true;
        if ((v.StartsWith("UTC", StringComparison.OrdinalIgnoreCase) || v.StartsWith("GMT", StringComparison.OrdinalIgnoreCase)) && v.Length > 3)
            v = v[3..];
        if (v.Length < 2 || (v[0] != '+' && v[0] != '-'))
            return false;
        var sign = v[0] == '-' ? -1 : 1;
        var digits = v[1..].Replace(":", "", StringComparison.Ordinal);
        if (digits.Length is not (1 or 2 or 4) || !digits.All(char.IsAsciiDigit))
            return false;
        var hours = int.Parse(digits.Length == 4 ? digits[..2] : digits, CultureInfo.InvariantCulture);
        var minutes = digits.Length == 4 ? int.Parse(digits[2..], CultureInfo.InvariantCulture) : 0;
        if (hours > 14 || minutes > 59)
            return false;
        offset = sign * new TimeSpan(hours, minutes, 0);
        return true;
    }

    /// <summary>Unix epoch in seconds, milliseconds, microseconds or nanoseconds (optionally with a fraction).</summary>
    public static bool TryEpoch(string? value, out DateTimeOffset timestamp)
    {
        timestamp = default;
        if (string.IsNullOrWhiteSpace(value))
            return false;
        var v = value.AsSpan().Trim();
        var dot = v.IndexOf('.');
        var integer = dot < 0 ? v : v[..dot];
        if (integer.Length is < 9 or > 19 || !IsDigits(integer) || (dot >= 0 && !IsDigits(v[(dot + 1)..])))
            return false;
        if (!long.TryParse(integer, NumberStyles.None, CultureInfo.InvariantCulture, out var n))
            return false;
        long ticks;
        switch (integer.Length)
        {
            case <= 11:   // seconds (+ fraction)
                ticks = n * TimeSpan.TicksPerSecond;
                if (dot >= 0)
                {
                    var frac = v[(dot + 1)..];
                    if (frac.Length > 7)
                        frac = frac[..7];
                    if (frac.Length > 0)
                        ticks += long.Parse(frac, NumberStyles.None, CultureInfo.InvariantCulture) * (long)Math.Pow(10, 7 - frac.Length);
                }
                break;
            case <= 14: ticks = n * TimeSpan.TicksPerMillisecond; break;
            case <= 17: ticks = n * 10; break;
            default: ticks = n / 100; break;
        }
        var max = new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero).UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks;
        if (ticks <= 0 || ticks >= max)
            return false;
        timestamp = DateTimeOffset.UnixEpoch.AddTicks(ticks);
        return true;
    }

    private static bool IsDigits(ReadOnlySpan<char> s)
    {
        foreach (var c in s)
            if (!char.IsAsciiDigit(c))
                return false;
        return true;
    }

    /// <summary>
    /// Any firewall time value: epochs, ISO 8601 ("+0100" offsets too), "2026-11-21 10:00:00 UTC" (zone word at the end),
    /// and the local formats of <see cref="LogTime"/>. <paramref name="zone"/> (a vendor tz field) is applied to local times.
    /// </summary>
    public static bool TryParse(string? value, LogParseContext context, out DateTimeOffset timestamp, string? zone = null)
    {
        timestamp = default;
        if (string.IsNullOrWhiteSpace(value) || value.Length > 64)
            return false;
        var v = value.Trim().Trim('"').Trim();
        if (TryEpoch(v, out timestamp))
            return true;

        TimeSpan? offset = TryOffset(zone, out var z) ? z : null;

        // Trailing zone word or offset after a space: "2026-11-21 10:00:00 UTC", "Nov 21 2026 10:00:00 +0100"
        var space = v.LastIndexOf(' ');
        if (space > 0 && TryOffset(v[(space + 1)..], out var trailing) && !v[(space + 1)..].All(char.IsAsciiDigit))
        {
            v = v[..space];
            offset = trailing;
        }
        else
        {
            // ISO with "+0100" -> "+01:00" (DateTimeOffset parsing wants the colon)
            var t = v.Length >= 5 ? v[^5..] : "";
            if (t.Length == 5 && t[0] is '+' or '-' && t[1..].All(char.IsAsciiDigit) && v.Contains('T') && v.Length > 10)
                v = v[..^2] + ":" + v[^2..];
        }

        var ctx = offset is null ? context : context with { DefaultOffset = offset.Value };
        return LogTime.TryParse(v, ctx, out timestamp);
    }

    /// <summary>Date and time in separate fields (FortiGate, Sophos): "2026-11-21" + "10:00:00", zone from a tz field.</summary>
    public static bool TryParse(string? date, string? time, string? zone, LogParseContext context, out DateTimeOffset timestamp)
    {
        timestamp = default;
        if (string.IsNullOrWhiteSpace(date) || string.IsNullOrWhiteSpace(time))
            return false;
        return TryParse(date.Trim() + " " + time.Trim(), context, out timestamp, zone);
    }

    /// <summary>Time from the usual key=value fields: date + time (+ tz), timestamp-like keys, a full "time", else null.</summary>
    public static DateTimeOffset? FromFields(KeyValueLine kv, LogParseContext context)
    {
        var zone = kv.Get(KvField.TimeZone);
        var date = kv.Get(KvField.Date);
        var time = kv.Get(KvField.Time);
        if (date is not null && time is not null && TryParse(date, time, zone, context, out var ts))
            return ts;
        if (kv.Get(KvField.Timestamp) is { } stamp && TryParse(stamp, context, out ts, zone))
            return ts;
        if (time is not null && TryParse(time, context, out ts, zone))
            return ts;
        if (date is not null && TryParse(date, context, out ts, zone))
            return ts;
        return null;
    }
}
