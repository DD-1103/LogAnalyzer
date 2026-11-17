using LogAnalyzer.Web.Models;

namespace LogAnalyzer.Web.Helpers;

public static class Format
{
    public static string Bytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB"];
        double size = bytes;
        var unit = 0;
        while (size >= 1024 && unit < units.Length - 1)
        {
            size /= 1024;
            unit++;
        }
        return $"{size:0.#} {units[unit]}";
    }

    public static string StatusBadge(LogFileStatus status) => status switch
    {
        LogFileStatus.Pending => "text-bg-secondary",
        LogFileStatus.Processing => "text-bg-info",
        LogFileStatus.Analyzing => "text-bg-primary",
        LogFileStatus.Completed => "text-bg-success",
        LogFileStatus.Failed => "text-bg-danger",
        LogFileStatus.Deleting => "text-bg-dark",
        _ => "text-bg-secondary"
    };

    public static bool IsBusy(LogFileStatus status) =>
        status is LogFileStatus.Pending or LogFileStatus.Processing or LogFileStatus.Analyzing or LogFileStatus.Deleting;

    public static string SeverityBadge(Severity severity) => severity switch
    {
        Severity.Critical => "text-bg-danger",
        Severity.High => "text-bg-warning",
        Severity.Medium => "text-bg-info",
        _ => "text-bg-secondary"
    };

    public static string AlertStatusBadge(AlertStatus status) => status switch
    {
        AlertStatus.New => "text-bg-danger",
        AlertStatus.Investigating => "text-bg-warning",
        AlertStatus.FalsePositive => "text-bg-secondary",
        AlertStatus.Closed => "text-bg-success",
        _ => "text-bg-secondary"
    };

    public static string AttackLabel(AttackType type) => type switch
    {
        AttackType.SqlInjection => "SQL injection",
        AttackType.Xss => "XSS",
        AttackType.PathTraversal => "Path traversal / LFI",
        AttackType.BruteForce => "Brute force",
        AttackType.Scanner => "Scanner",
        AttackType.DirectoryEnumeration => "Directory enumeration",
        AttackType.Anomaly => "Anomaly",
        _ => type.ToString()
    };

    public static string Percent(double value) => (value * 100).ToString("0.0") + "%";

    /// <summary>AbuseIPDB confidence score colour: 75+ = very likely malicious.</summary>
    public static string AbuseBadge(int score) => score switch
    {
        >= 75 => "text-bg-danger",
        >= 25 => "text-bg-warning",
        _ => "text-bg-secondary"
    };

    /// <summary>
    /// Makes a value safe for CSV: quotes it, and neutralises leading =, +, -, @ so that
    /// attacker-controlled log data cannot run as a formula when the file is opened in Excel (CSV injection).
    /// </summary>
    public static string Csv(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return "\"\"";
        // Spreadsheets skip leading spaces / line breaks and also accept full-width signs as formula starters.
        var first = value.TrimStart(' ', '\u00A0', '\u3000');
        if (value[0] is '\t' or '\r' or '\n' || (first.Length > 0 && FormulaStart.Contains(first[0])))
            value = "'" + value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }

    private const string FormulaStart = "=+-@\t\r\n\uFF1D\uFF0B\uFF0D\uFF20";

    public static string HttpStatusClass(int code) => code switch
    {
        >= 500 => "text-danger",
        >= 400 => "text-warning",
        >= 300 => "text-info",
        _ => "text-success"
    };

    public static string VerdictBadge(ThreatVerdict verdict) => verdict switch
    {
        ThreatVerdict.Malicious => "text-bg-danger",
        ThreatVerdict.Suspicious => "text-bg-warning",
        ThreatVerdict.Benign => "text-bg-success",
        ThreatVerdict.Error => "text-bg-dark border border-danger-subtle",
        ThreatVerdict.Skipped => "text-bg-dark border",
        _ => "text-bg-secondary"
    };

    /// <summary>Compact label for tables: "AbuseIPDB 87%", "GreyNoise benign", "VT 5/94".</summary>
    public static string ReputationShort(IpReputation r)
    {
        var a = r.GetAttributes();
        return r.Provider switch
        {
            "AbuseIPDB" when r.Score is int s => $"AbuseIPDB {s}%",
            "GreyNoise" when a.TryGetValue("Classification", out var c) => $"GreyNoise {c}",
            "GreyNoise" when r.Verdict == ThreatVerdict.NotFound => "GreyNoise: not noise",
            "VirusTotal" when a.TryGetValue("Malicious", out var m) => $"VT {m} malicious",
            _ => $"{r.Provider} {r.Verdict.ToString().ToLowerInvariant()}"
        };
    }

    public static string TimeAgo(DateTime utc)
    {
        var d = DateTime.UtcNow - utc;
        return d.TotalMinutes < 1 ? "just now"
            : d.TotalHours < 1 ? $"{(int)d.TotalMinutes} min ago"
            : d.TotalDays < 1 ? $"{(int)d.TotalHours} h ago"
            : $"{(int)d.TotalDays} d ago";
    }
}
