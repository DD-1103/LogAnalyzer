using System.Text.Json;
using Microsoft.AspNetCore.Identity;

namespace LogAnalyzer.Web.Models;

public class AppUser : IdentityUser
{
    public string FullName { get; set; } = string.Empty;

    /// <summary>Disabled by an administrator: cannot sign in (the account and its history are kept).</summary>
    public bool IsDisabled { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }

    /// <summary>Set for seeded accounts and passwords chosen by an administrator: the user must pick a new password first.</summary>
    public bool MustChangePassword { get; set; }

    // When the user last opened these pages; drives the "new since last visit" nav badges.
    public DateTime? AlertsSeenAt { get; set; }
    public DateTime? RulesSeenAt { get; set; }
}

public class LogFile
{
    public int Id { get; set; }
    public string FileName { get; set; } = string.Empty;
    public long SizeBytes { get; set; }
    public DateTime UploadedAt { get; set; } = DateTime.UtcNow;

    public string UploadedById { get; set; } = string.Empty;
    public AppUser? UploadedBy { get; set; }

    public LogFileStatus Status { get; set; } = LogFileStatus.Pending;
    public int TotalLines { get; set; }
    public int ParsedLines { get; set; }
    public int FailedLines { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime? ProcessedAt { get; set; }

    /// <summary>Notes from the last detection run, e.g. rules whose regex timed out.</summary>
    public string? DetectionWarnings { get; set; }

    // Performance measurements for RQ3 (parse + bulk insert, and detection incl. anomaly model).
    public long? ParseMilliseconds { get; set; }
    public long? DetectionMilliseconds { get; set; }

    /// <summary>Times processing was started since the last success; protects against crash loops on start-up.</summary>
    public int ProcessingAttempts { get; set; }

    public ICollection<LogEvent> Events { get; set; } = new List<LogEvent>();
    public ICollection<Alert> Alerts { get; set; } = new List<Alert>();
}

/// <summary>
/// Requests per hour of one log file (all / flagged as malicious), computed once after detection so the dashboard
/// does not have to aggregate millions of events on every page load.
/// </summary>
public class LogFileHourStat
{
    public int LogFileId { get; set; }
    /// <summary>Start of the hour, in the time zone of the log (as written in the log lines).</summary>
    public DateTime Hour { get; set; }
    public int Total { get; set; }
    public int Flagged { get; set; }
}

/// <summary>One parsed line of an access log (Combined Log Format).</summary>
public class LogEvent
{
    public long Id { get; set; }

    public int LogFileId { get; set; }
    public LogFile? LogFile { get; set; }

    public int LineNumber { get; set; }
    public string ClientIp { get; set; } = string.Empty;
    public DateTimeOffset Timestamp { get; set; }
    public string Method { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string? Protocol { get; set; }
    public int StatusCode { get; set; }
    public long? ResponseSize { get; set; }
    public string? Referrer { get; set; }
    public string? UserAgent { get; set; }
    public string RawLine { get; set; } = string.Empty;
}

public class DetectionRule
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public AttackType AttackType { get; set; }
    public Severity Severity { get; set; }
    public RuleKind Kind { get; set; }

    // Signature rules
    public RuleField Field { get; set; } = RuleField.Url;
    public string? Pattern { get; set; }

    // Threshold rules: count events matching the filters per IP inside a sliding window
    public int? Threshold { get; set; }
    public int? WindowSeconds { get; set; }
    public string? MethodFilter { get; set; }   // e.g. "POST"
    public string? PathPattern { get; set; }    // regex on URL, e.g. "login"
    public int? StatusFilter { get; set; }      // e.g. 404

    // Anomaly rules: Threshold = minimum requests per IP, ScoreThreshold = Isolation Forest score (0.5-1)
    public double? ScoreThreshold { get; set; }

    public bool IsEnabled { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<Alert> Alerts { get; set; } = new List<Alert>();
}

public class Alert
{
    public long Id { get; set; }
    public string Title { get; set; } = string.Empty;

    public int RuleId { get; set; }
    public DetectionRule? Rule { get; set; }

    public int LogFileId { get; set; }
    public LogFile? LogFile { get; set; }

    public string SourceIp { get; set; } = string.Empty;
    public AttackType AttackType { get; set; }
    public Severity Severity { get; set; }
    public AlertStatus Status { get; set; } = AlertStatus.New;

    public DateTimeOffset FirstSeen { get; set; }
    public DateTimeOffset LastSeen { get; set; }
    public int EventCount { get; set; }

    // Anomaly alerts: Isolation Forest score and the features that made the IP stand out.
    public double? Score { get; set; }
    public string? Details { get; set; }

    // Set when threat intelligence changed the severity (e.g. GreyNoise says the IP is a benign scanner).
    public Severity? OriginalSeverity { get; set; }
    public string? SeverityNote { get; set; }

    public string? Notes { get; set; }
    public string? AssignedToId { get; set; }
    public AppUser? AssignedTo { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<AlertEvidence> Evidence { get; set; } = new List<AlertEvidence>();
}

/// <summary>Links an alert to the log lines that triggered it.</summary>
public class AlertEvidence
{
    public long Id { get; set; }
    public long AlertId { get; set; }
    public Alert? Alert { get; set; }
    public long LogEventId { get; set; }
    public LogEvent? LogEvent { get; set; }
}

/// <summary>Cached enrichment data for an IP address.</summary>
public class IpInfo
{
    public string Ip { get; set; } = string.Empty;
    public string? CountryCode { get; set; }
    public string? CountryName { get; set; }
    public string? City { get; set; }
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
    public int? AbuseScore { get; set; }
    public DateTime LastChecked { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Cached answer of one threat-intelligence provider (AbuseIPDB, GreyNoise, VirusTotal) about one IP.
/// One row per (Ip, Provider); refreshed after <c>Enrichment:CacheDays</c> or on demand.
/// </summary>
public class IpReputation
{
    public long Id { get; set; }
    public string Ip { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty;
    public ThreatVerdict Verdict { get; set; }

    /// <summary>0-100 where the provider gives a score (AbuseIPDB confidence, VirusTotal % of engines).</summary>
    public int? Score { get; set; }

    public string? Summary { get; set; }

    /// <summary>Provider-specific details as a JSON object of label -> value (ISP, last seen, ...).</summary>
    public string? AttributesJson { get; set; }

    public string? Error { get; set; }
    public DateTime CheckedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Set when the last refresh failed (rate limit, key rejected, timeout) but an earlier good answer was kept:
    /// the verdict above is still the one from <see cref="CheckedAt"/>.
    /// </summary>
    public DateTime? LastAttemptAt { get; set; }
    public string? LastAttemptError { get; set; }

    /// <summary>A real answer from the provider (not an error or a skipped lookup).</summary>
    public bool HasVerdict => Verdict is not (ThreatVerdict.Error or ThreatVerdict.Skipped);

    public Dictionary<string, string> GetAttributes()
    {
        if (string.IsNullOrEmpty(AttributesJson))
            return [];
        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, string>>(AttributesJson) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}

/// <summary>One audited user action (login, upload, rule change, triage, export...).</summary>
public class AuditEntry
{
    public long Id { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string? UserName { get; set; }
    public string Action { get; set; } = string.Empty;
    public string? Target { get; set; }
    public string? Details { get; set; }
    public string? IpAddress { get; set; }
}
