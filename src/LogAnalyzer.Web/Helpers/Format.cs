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
        _ => "text-bg-secondary"
    };

    public static bool IsBusy(LogFileStatus status) =>
        status is LogFileStatus.Pending or LogFileStatus.Processing or LogFileStatus.Analyzing;

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
        if ("=+-@\t\r".Contains(value[0]))
            value = "'" + value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }

    public static string HttpStatusClass(int code) => code switch
    {
        >= 500 => "text-danger",
        >= 400 => "text-warning",
        >= 300 => "text-info",
        _ => "text-success"
    };
}
