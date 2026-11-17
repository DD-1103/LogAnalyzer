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
    string? UserAgent);

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
        @"^(?<ip>\S+)\s+\S+\s+\S+\s+\[(?<time>[^\]]+)\]\s+""(?<req>(?:[^""\\]|\\.)*)""\s+(?<status>\d{3})\s+(?<size>\S+)(?:\s+""(?<ref>(?:[^""\\]|\\.)*)""\s+""(?<ua>(?:[^""\\]|\\.)*)"")?",
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
