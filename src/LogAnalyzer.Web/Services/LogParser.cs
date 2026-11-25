using System.Globalization;
using System.Text.RegularExpressions;

namespace LogAnalyzer.Web.Services;

public sealed record ParsedLine(
    string ClientIp,
    DateTimeOffset Timestamp,
    string Method,
    string Url,
    string? Protocol,
    int StatusCode,
    long? ResponseSize,
    string? Referrer,
    string? UserAgent)
{
    // Firewall / network fields (see LogEvent). Web access lines leave them null.
    public string? DestinationIp { get; init; }
    public int? SourcePort { get; init; }
    public int? DestinationPort { get; init; }
    public string? Transport { get; init; }
    public LogAnalyzer.Web.Models.FirewallAction? Action { get; init; }
    public string? EventType { get; init; }
    public string? RuleName { get; init; }
    public string? ThreatName { get; init; }
    public string? Device { get; init; }

    /// <summary>
    /// Builds a firewall / network event in the shared shape: ClientIp = source address (canonical, "-" when the line
    /// has none), Method = action word ("DENY", "ALLOW", ... or "EVENT"), Url = message, StatusCode = 0.
    /// Transport and EventType are lower-cased; ports outside 0-65535 are dropped. Log text is attacker-controlled:
    /// anything that is not a literal IP address is never stored as an address, control characters become spaces.
    /// </summary>
    public static ParsedLine Network(
        string? sourceIp,
        DateTimeOffset timestamp,
        LogAnalyzer.Web.Models.FirewallAction action,
        string message,
        string? destinationIp = null,
        int? sourcePort = null,
        int? destinationPort = null,
        string? transport = null,
        string? eventType = null,
        string? ruleName = null,
        string? threatName = null,
        string? device = null,
        long? bytes = null)
    {
        static int? Port(int? p) => p is >= 0 and <= 65535 ? p : null;
        static string? Clean(string? v)
        {
            if (string.IsNullOrWhiteSpace(v))
                return null;
            var s = NoControlCharacters(v).Trim();
            return s.Length == 0 || s == "-" ? null : s;
        }
        var src = Address(sourceIp);
        var dst = Address(destinationIp);
        return new ParsedLine(
            ClientIp: src ?? "-",
            Timestamp: timestamp,
            Method: action == LogAnalyzer.Web.Models.FirewallAction.Unknown ? "EVENT" : action.ToString().ToUpperInvariant(),
            Url: NoControlCharacters(message).Trim(),
            Protocol: null,
            StatusCode: 0,
            ResponseSize: bytes,
            Referrer: null,
            UserAgent: null)
        {
            DestinationIp = dst,
            SourcePort = Port(sourcePort),
            DestinationPort = Port(destinationPort),
            Transport = Clean(transport)?.ToLowerInvariant(),
            Action = action,
            EventType = Clean(eventType)?.ToLowerInvariant(),
            RuleName = Clean(ruleName),
            ThreatName = Clean(threatName),
            Device = Clean(device)
        };
    }

    /// <summary>
    /// Canonical text of a literal IP address (four decimal parts without leading zeros, or IPv6; a zone id is dropped);
    /// null for anything else.
    /// </summary>
    private static string? Address(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        var v = value.Trim();
        var zone = v.IndexOf('%');
        if (zone > 0 && v.AsSpan(0, zone).Contains(':'))
            v = v[..zone];
        return IsIpLiteral(v) ? IpAddressPolicy.Canonical(v) : null;
    }

    /// <summary>
    /// True for "203.0.113.5" (exactly four decimal parts, no leading zeros) and IPv6 without brackets, port or zone.
    /// IPAddress.TryParse alone also reads "1.2", "12345", "0x7f.0.0.1" and octal "010.0.0.1".
    /// </summary>
    public static bool IsIpLiteral(ReadOnlySpan<char> value)
    {
        if (value.Length is < 2 or > 45)
            return false;
        if (value.Contains(':'))
        {
            foreach (var c in value)
                if (!char.IsAsciiHexDigit(c) && c is not (':' or '.'))
                    return false;
            return System.Net.IPAddress.TryParse(value, out var v6) && v6.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        }
        int dots = 0, digits = 0, number = 0;
        foreach (var c in value)
        {
            if (c == '.')
            {
                if (digits == 0 || ++dots > 3)
                    return false;
                digits = number = 0;
                continue;
            }
            if (!char.IsAsciiDigit(c) || (digits > 0 && number == 0))
                return false;
            digits++;
            number = number * 10 + (c - '0');
            if (number > 255)
                return false;
        }
        return dots == 3 && digits > 0;
    }

    private static string NoControlCharacters(string text)
    {
        foreach (var c in text)
            if (char.IsControl(c))
                return string.Create(text.Length, text, static (span, t) =>
                {
                    for (var i = 0; i < span.Length; i++)
                        span[i] = char.IsControl(t[i]) ? ' ' : t[i];
                });
        return text;
    }
}

public interface ILogParser
{
    bool TryParse(string line, out ParsedLine? result);
}

/// <summary>
/// Parses Apache / Nginx access logs in Common or Combined Log Format:
/// 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326 "http://ref/" "Mozilla/4.08"
/// </summary>
public sealed partial class CombinedLogParser : ILogParser
{
    // Quoted fields allow escaped quotes (\") which attackers often put in user agents.
    [GeneratedRegex(
        @"^(?<ip>\S+)\s+\S+\s+\S+\s+\[(?<time>[^\]]+)\]\s+""(?<req>(?:[^""\\]|\\.)*)""\s+(?<status>[0-9]{3})\s+(?<size>\S+)(?:\s+""(?<ref>(?:[^""\\]|\\.)*)""\s+""(?<ua>(?:[^""\\]|\\.)*)"")?",
        RegexOptions.CultureInvariant)]
    private static partial Regex LineRegex();

    private static readonly string[] TimeFormats = ["dd/MMM/yyyy:HH:mm:ss zzz", "d/MMM/yyyy:HH:mm:ss zzz"];

    public bool TryParse(string line, out ParsedLine? result)
    {
        result = null;
        if (string.IsNullOrWhiteSpace(line))
            return false;

        var m = LineRegex().Match(line);
        if (!m.Success)
            return false;

        if (!TryParseTime(m.Groups["time"].Value, out var timestamp))
            return false;

        var (method, url, protocol) = SplitRequest(m.Groups["req"].Value);

        long? size = long.TryParse(m.Groups["size"].Value, out var s) ? s : null;

        result = new ParsedLine(
            ClientIp: IpAddressPolicy.Canonical(m.Groups["ip"].Value),
            Timestamp: timestamp,
            Method: method,
            Url: url,
            Protocol: protocol,
            StatusCode: int.Parse(m.Groups["status"].Value, CultureInfo.InvariantCulture),
            ResponseSize: size,
            Referrer: NullIfDash(m.Groups["ref"]),
            UserAgent: NullIfDash(m.Groups["ua"]));
        return true;
    }

    // "10/Oct/2000:13:55:36 -0700" -> .NET needs the offset as "-07:00"
    private static bool TryParseTime(string value, out DateTimeOffset timestamp)
    {
        var v = value.Trim();
        if (v.Length >= 5)
        {
            var offset = v[^5..];
            if ((offset[0] == '+' || offset[0] == '-') && offset[1..].All(char.IsDigit))
                v = v[..^2] + ":" + v[^2..];
        }
        return DateTimeOffset.TryParseExact(v, TimeFormats, CultureInfo.InvariantCulture,
            DateTimeStyles.None, out timestamp);
    }

    // Scanners often send malformed request lines, so don't assume "METHOD URL PROTOCOL".
    private static (string Method, string Url, string? Protocol) SplitRequest(string request)
    {
        var parts = request.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        return parts.Length switch
        {
            3 => (parts[0], parts[1], parts[2]),
            2 => (parts[0], parts[1], null),
            _ => ("-", request, null)
        };
    }

    private static string? NullIfDash(Group g) =>
        !g.Success || g.Value is "" or "-" ? null : g.Value;
}
