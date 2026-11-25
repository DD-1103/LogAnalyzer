using System.Globalization;
using LogAnalyzer.Web.Models;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>
/// Small helpers shared by the positional / free-text firewall formats (Palo Alto, Cisco ASA, pfSense, netfilter,
/// Windows Firewall, Juniper, WatchGuard, MikroTik, AWS VPC). Everything here is allocation-light and never throws.
/// </summary>
internal static class PositionalFormatHelpers
{
    /// <summary>
    /// True for a literal IPv4 (exactly four dotted parts) or IPv6 address (a zone id is allowed), see
    /// <see cref="ParsedLine.IsIpLiteral"/>.
    /// </summary>
    public static bool IsIp(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 64)
            return false;
        var s = value.AsSpan();
        var zone = s.IndexOf('%');
        return ParsedLine.IsIpLiteral(zone > 0 && s[..zone].Contains(':') ? s[..zone] : s);
    }

    public static int? Port(string? value) =>
        int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var p) && p is >= 0 and <= 65535 ? p : null;

    public static long? Long(string? value) =>
        long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var v) ? v : null;

    /// <summary>"6" -> "tcp", "TCP" -> "tcp", unknown numbers stay numbers, empty / "-" -> null.</summary>
    public static string? Transport(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value == "-")
            return null;
        var v = value.Trim();
        return v switch
        {
            "1" => "icmp",
            "2" => "igmp",
            "6" => "tcp",
            "17" => "udp",
            "47" => "gre",
            "50" => "esp",
            "51" => "ah",
            "58" => "ipv6-icmp",
            "132" => "sctp",
            _ when v.Equals("icmpv6", StringComparison.OrdinalIgnoreCase) || v.Equals("ipv6-icmp", StringComparison.OrdinalIgnoreCase)
                   || v.Equals("icmp6", StringComparison.OrdinalIgnoreCase) => "ipv6-icmp",
            _ => v.ToLowerInvariant()
        };
    }

    /// <summary>Vendor action word -> normalised action (see the format docs for the vendor-specific words).</summary>
    public static FirewallAction Action(string? word)
    {
        if (string.IsNullOrWhiteSpace(word))
            return FirewallAction.Unknown;
        var w = word.Trim().ToLowerInvariant().Replace(' ', '-');
        return w switch
        {
            "allow" or "allowed" or "accept" or "accepted" or "permit" or "permitted" or "pass" or "passed" or "built"
                or "teardown" or "est-allowed" or "established" or "create" or "close" => FirewallAction.Allow,
            "deny" or "denied" or "block" or "blocked" or "block-url" or "block-ip" or "sinkhole" or "discard" => FirewallAction.Deny,
            "drop" or "dropped" or "drop-icmp" or "drop-all-packets" or "random-drop" => FirewallAction.Drop,
            "reject" or "rejected" or "reset" or "reset-client" or "reset-server" or "reset-both" => FirewallAction.Reject,
            "alert" or "detect" or "detected" or "alarm" or "monitor" or "syncookie-sent" => FirewallAction.Alert,
            _ => FirewallAction.Unknown
        };
    }

    /// <summary>"203.0.113.5/51234" -> ("203.0.113.5", 51234); "outside:203.0.113.5/22" also works (interface dropped).</summary>
    public static bool TrySplitSlash(string? value, out string ip, out int? port)
    {
        ip = string.Empty;
        port = null;
        if (string.IsNullOrEmpty(value))
            return false;
        var v = value;
        var slash = v.LastIndexOf('/');
        string addr = slash >= 0 ? v[..slash] : v;
        if (slash >= 0)
            port = Port(v[(slash + 1)..]);
        // Interface prefix "outside:" (ASA) - only when what follows is an IPv4 address or the prefix has no colon itself.
        if (!IsIp(addr))
        {
            var colon = addr.IndexOf(':');
            if (colon < 0 || !IsIp(addr[(colon + 1)..]))
                return false;
            addr = addr[(colon + 1)..];
        }
        ip = addr;
        return true;
    }

    /// <summary>
    /// Splits a CSV line (comma separated, double quotes around fields that contain commas, "" = escaped quote).
    /// Returns false for an unterminated quote.
    /// </summary>
    public static bool TrySplitCsv(string line, int start, List<string> fields, int maxFields = 512)
    {
        fields.Clear();
        System.Text.StringBuilder? sb = null;
        var i = start;
        while (fields.Count < maxFields)
        {
            if (i < line.Length && line[i] == '"')
            {
                sb ??= new System.Text.StringBuilder();
                sb.Clear();
                i++;
                var closed = false;
                while (i < line.Length)
                {
                    var c = line[i];
                    if (c == '"')
                    {
                        if (i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i += 2; continue; }
                        closed = true;
                        i++;
                        break;
                    }
                    sb.Append(c);
                    i++;
                }
                if (!closed)
                    return false;
                fields.Add(sb.ToString());
                // anything between the closing quote and the next comma is ignored
                var next = line.IndexOf(',', i);
                if (next < 0)
                    return true;
                i = next + 1;
            }
            else
            {
                var comma = line.IndexOf(',', i);
                if (comma < 0)
                {
                    fields.Add(line[i..]);
                    return true;
                }
                fields.Add(line[i..comma]);
                i = comma + 1;
            }
        }
        return true;
    }

    /// <summary>Field value or null for missing / empty / "-".</summary>
    public static string? At(IReadOnlyList<string> fields, int index)
    {
        if (index < 0 || index >= fields.Count)
            return null;
        var v = fields[index];
        return string.IsNullOrWhiteSpace(v) || v == "-" ? null : v.Trim();
    }

    /// <summary>Space-separated tokens of a string (no empty entries), cheap and allocation-bounded.</summary>
    public static string[] Tokens(string text) => text.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>
    /// Value of key="value" or key=value in a free-text message (first occurrence, key must start a token). Text inside
    /// another key's quoted value is never searched: a user name may contain anything.
    /// </summary>
    public static string? QuotedValue(string text, string key)
    {
        var idx = FindKey(text, key);
        if (idx < 0)
            return null;
        var start = idx + key.Length + 1;
        if (start >= text.Length)
            return null;
        if (text[start] == '"')
        {
            var sb = new System.Text.StringBuilder();
            for (var i = start + 1; i < text.Length; i++)
            {
                var c = text[i];
                if (c == '\\' && i + 1 < text.Length) { sb.Append(text[++i]); continue; }
                if (c == '"') return sb.ToString();
                sb.Append(c);
            }
            return null;
        }
        var end = text.IndexOf(' ', start);
        return end < 0 ? text[start..] : text[start..end];
    }

    private static int FindKey(string text, string key)
    {
        var tokenStart = true;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (tokenStart && c == key[0] && i + key.Length < text.Length && text[i + key.Length] == '='
                && string.CompareOrdinal(text, i, key, 0, key.Length) == 0)
                return i;
            if (c == '"')
            {
                for (i++; i < text.Length && text[i] != '"'; i++)
                    if (text[i] == '\\')
                        i++;
            }
            tokenStart = c is ' ' or '[' or ',' or '\t';
        }
        return -1;
    }

    /// <summary>The vendor's own time stamp when it parses, else the syslog header's.</summary>
    public static bool TryTime(string? vendorValue, SyslogEnvelope? envelope, LogParseContext context, out DateTimeOffset timestamp)
    {
        if (!string.IsNullOrWhiteSpace(vendorValue) && LogTime.TryParse(vendorValue, context, out timestamp))
            return true;
        if (envelope?.Timestamp is { } t)
        {
            timestamp = t;
            return true;
        }
        timestamp = default;
        return false;
    }

    /// <summary>"ip:port" text for messages ("[v6]:port" for IPv6).</summary>
    public static string Endpoint(string? ip, int? port)
    {
        if (string.IsNullOrEmpty(ip))
            return "?";
        if (port is null)
            return ip;
        return ip.Contains(':') ? $"[{ip}]:{port}" : $"{ip}:{port}";
    }

    /// <summary>Shortens a message to a readable length for the event list.</summary>
    public static string Short(string text, int max = 400) => text.Length <= max ? text.Trim() : text[..max].TrimEnd() + "...";
}
