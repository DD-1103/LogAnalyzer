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

    private static readonly string[] YearlessFormats = ["MMM d HH:mm:ss", "MMM dd HH:mm:ss", "MMM d HH:mm:ss.FFFFFF", "MMM dd HH:mm:ss.FFFFFF"];

    /// <summary>
    /// ISO 8601 with offset or "Z", the common local formats above (interpreted with
    /// <see cref="LogParseContext.DefaultOffset"/>), syslog "Nov 21 10:00:00" (year from the reference time; a date
    /// more than a day in the future is moved to the previous year) and Unix epoch seconds / milliseconds.
    /// </summary>
    public static bool TryParse(string? value, LogParseContext context, out DateTimeOffset timestamp)
    {
        timestamp = default;
        if (string.IsNullOrWhiteSpace(value))
            return false;
        var v = string.Join(' ', value.Trim().Trim('"').Split(' ', StringSplitOptions.RemoveEmptyEntries));

        // Unix epoch (AWS VPC flow logs, Meraki "1700000000.123", JSON exports)
        if (v.Length is >= 9 and <= 17 && double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out var epoch)
            && v.All(c => char.IsDigit(c) || c == '.'))
        {
            var ms = epoch > 1e11 ? epoch : epoch * 1000;
            if (ms is > 0 and < 4102444800000)   // before 2100
            {
                timestamp = DateTimeOffset.FromUnixTimeMilliseconds((long)ms);
                return true;
            }
            return false;
        }

        // With an explicit offset or Z
        if ((v.EndsWith('Z') || HasOffset(v)) &&
            DateTimeOffset.TryParse(v, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out timestamp))
            return true;

        if (DateTime.TryParseExact(v, LocalFormats, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out var local))
        {
            timestamp = new DateTimeOffset(DateTime.SpecifyKind(local, DateTimeKind.Unspecified), context.DefaultOffset);
            return true;
        }

        if (DateTime.TryParseExact(v, YearlessFormats, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out var noYear))
        {
            var reference = context.ReferenceTime.ToOffset(context.DefaultOffset);
            var guess = new DateTimeOffset(reference.Year, noYear.Month, Math.Min(noYear.Day, DateTime.DaysInMonth(reference.Year, noYear.Month)),
                noYear.Hour, noYear.Minute, noYear.Second, context.DefaultOffset).AddTicks(noYear.Ticks % TimeSpan.TicksPerSecond);
            if (guess > reference.AddDays(1))
                guess = guess.AddYears(-1);
            timestamp = guess;
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
        return (t5[0] == '+' || t5[0] == '-') && t5[1..].All(char.IsDigit) && v.Contains(':');
    }
}
