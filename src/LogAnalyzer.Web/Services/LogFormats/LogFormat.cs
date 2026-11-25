using System.Globalization;
using LogAnalyzer.Web.Models;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>Result of one line: an event, a line that is not an event (header, comment, unrelated syslog), or garbage.</summary>
public enum ParseOutcome
{
    Parsed,
    /// <summary>Not an event but expected in this format (W3C "#Fields" header, comment, device message without traffic).</summary>
    Skipped,
    Failed
}

/// <summary>
/// Settings for one file. <see cref="ReferenceTime"/> fills in the year for syslog time stamps that have none
/// ("Nov 21 10:00:00"); <see cref="DefaultOffset"/> is used for time stamps without a time zone (firewalls usually
/// log local time without an offset; default UTC).
/// </summary>
public sealed record LogParseContext(DateTimeOffset ReferenceTime, TimeSpan DefaultOffset)
{
    public static LogParseContext Default => new(DateTimeOffset.UtcNow, TimeSpan.Zero);
}

/// <summary>A log format the app can read. Implementations are found by reflection (<see cref="LogFormatRegistry"/>).</summary>
public interface ILogFormat
{
    /// <summary>Stable id used in URLs and the upload form, lower case, e.g. "fortigate".</summary>
    string Id { get; }

    /// <summary>Shown to users, e.g. "Fortinet FortiGate".</summary>
    string DisplayName { get; }

    LogSource Source { get; }

    /// <summary>
    /// Preference when two formats read the same sample equally well: vendor formats 100, vendor-neutral
    /// structured formats (CEF, LEEF, JSON) 50, the generic key=value reader 10.
    /// </summary>
    int Specificity { get; }

    /// <summary>A new parser for one file (parsers may keep state, e.g. the W3C "#Fields" header).</summary>
    ILineParser CreateParser(LogParseContext context);
}

public interface ILineParser
{
    /// <summary>Must never throw and must be fast on non-matching lines (it is also tried as a fallback).</summary>
    ParseOutcome Parse(string line, out ParsedLine? result);
}

/// <summary>Apache / Nginx access logs (the original format) as an <see cref="ILogFormat"/>.</summary>
public sealed class WebAccessLogFormat : ILogFormat
{
    public const string FormatId = "combined";
    public string Id => FormatId;
    public string DisplayName => "Apache / Nginx access log";
    public LogSource Source => LogSource.WebAccess;
    public int Specificity => 100;
    public ILineParser CreateParser(LogParseContext context) => new Parser();

    private sealed class Parser : ILineParser
    {
        private readonly CombinedLogParser _inner = new();
        public ParseOutcome Parse(string line, out ParsedLine? result) =>
            _inner.TryParse(line, out result) && result is not null ? ParseOutcome.Parsed : ParseOutcome.Failed;
    }
}

/// <summary>Shared time-stamp parsing for firewall formats.</summary>
public static class LogTime
{
    private static readonly string[] LocalFormats =
    [
        "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd HH:mm:ss.FFFFFFF", "yyyy/MM/dd HH:mm:ss", "yyyy/MM/dd HH:mm:ss.FFFFFFF",
        "yyyy-MM-ddTHH:mm:ss", "yyyy-MM-ddTHH:mm:ss.FFFFFFF", "MMM d yyyy HH:mm:ss", "MMM dd yyyy HH:mm:ss",
        "MMM d yyyy HH:mm:ss.FFF", "MMM dd yyyy HH:mm:ss.FFF", "dd/MMM/yyyy:HH:mm:ss", "d/MMM/yyyy:HH:mm:ss",
        "yyyyMMddHHmmss", "MM/dd/yyyy HH:mm:ss", "dd.MM.yyyy HH:mm:ss"
    ];

    private static readonly string[] YearlessFormats =
        ["yyyy MMM d HH:mm:ss", "yyyy MMM dd HH:mm:ss", "yyyy MMM d HH:mm:ss.FFFFFF", "yyyy MMM dd HH:mm:ss.FFFFFF"];

    /// <summary>Time stamps outside this range are device errors or forged (date arithmetic on them would overflow).</summary>
    private const int MinYear = 1970, MaxYear = 2100;

    /// <summary>
    /// ISO 8601 with offset or "Z", the common local formats above (interpreted with
    /// <see cref="LogParseContext.DefaultOffset"/>), syslog "Nov 21 10:00:00" (year from the reference time; a date
    /// more than a day in the future is moved to the previous year, "Feb 29" to the last leap year) and Unix epoch
    /// seconds / milliseconds. Only the years 1970 to 2100 are accepted. Never throws.
    /// </summary>
    public static bool TryParse(string? value, LogParseContext context, out DateTimeOffset timestamp)
    {
        timestamp = default;
        if (string.IsNullOrWhiteSpace(value))
            return false;
        var v = string.Join(' ', value.Trim().Trim('"').Split(' ', StringSplitOptions.RemoveEmptyEntries));

        // Unix epoch (AWS VPC flow logs, Meraki "1700000000.123", JSON exports)
        if (v.Length is >= 9 and <= 17 && v.All(c => char.IsAsciiDigit(c) || c == '.')
            && double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out var epoch))
        {
            var ms = epoch > 1e11 ? epoch : epoch * 1000;
            if (ms is > 0 and < 4102444800000)   // before 2100
            {
                timestamp = DateTimeOffset.FromUnixTimeMilliseconds((long)ms);
                return true;
            }
            // "20261121100000" is no epoch: the local formats below may read it
        }

        // With an explicit offset or Z (a value without a date such as "10:00:00Z" would be completed with today)
        if ((v.EndsWith('Z') || HasOffset(v)) && HasYear(v) &&
            DateTimeOffset.TryParse(v, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeUniversal, out var zoned)
            && InRange(zoned.UtcDateTime))
        {
            timestamp = zoned;
            return true;
        }

        if (DateTime.TryParseExact(v, LocalFormats, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out var local))
            return TryLocal(local, context.DefaultOffset, out timestamp);

        // 2000 = a leap year, so "Feb 29" can be read whatever the current year is
        if (DateTime.TryParseExact("2000 " + v, YearlessFormats, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out var noYear))
        {
            var reference = context.ReferenceTime;
            for (var year = reference.Year + 1; year >= Math.Max(MinYear, reference.Year - 8); year--)
            {
                if (year > MaxYear || noYear.Day > DateTime.DaysInMonth(year, noYear.Month))
                    continue;
                var candidate = new DateTime(year, noYear.Month, noYear.Day).Add(noYear.TimeOfDay);
                if (TryLocal(candidate, context.DefaultOffset, out var guess) && guess - reference <= TimeSpan.FromDays(1))
                {
                    timestamp = guess;
                    return true;
                }
            }
        }
        return false;
    }

    /// <summary>A local date and time with an offset; false outside the years 1970 to 2100 (the constructor would throw at the edges).</summary>
    public static bool TryLocal(DateTime local, TimeSpan offset, out DateTimeOffset timestamp)
    {
        timestamp = default;
        if (!InRange(local) || offset.Ticks % TimeSpan.TicksPerMinute != 0 || offset.Duration() > TimeSpan.FromHours(14))
            return false;
        timestamp = new DateTimeOffset(DateTime.SpecifyKind(local, DateTimeKind.Unspecified), offset);
        return true;
    }

    private static bool InRange(DateTime t) => t.Year is >= MinYear and <= MaxYear;

    /// <summary>Contains a four-digit year (not just the digits of a "+0200" offset).</summary>
    private static bool HasYear(string v)
    {
        var run = 0;
        for (var i = 0; i < v.Length - 5; i++)   // not the digits of a "+0200" offset
        {
            run = char.IsAsciiDigit(v[i]) ? run + 1 : 0;
            if (run == 4)
                return true;
        }
        return false;
    }

    private static bool HasOffset(string v)
    {
        // "...+02:00", "...-0700"
        if (v.Length < 6)
            return false;
        var tail = v[^6..];
        if ((tail[0] == '+' || tail[0] == '-') && tail[3] == ':')
            return true;
        var t5 = v[^5..];
        return (t5[0] == '+' || t5[0] == '-') && t5[1..].All(char.IsAsciiDigit) && v.Contains(':');
    }
}
