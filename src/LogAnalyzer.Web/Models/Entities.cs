using Microsoft.AspNetCore.Identity;

namespace LogAnalyzer.Web.Models;

public class AppUser : IdentityUser
{
    public string FullName { get; set; } = string.Empty;

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

    public ICollection<LogEvent> Events { get; set; } = new List<LogEvent>();
    public ICollection<Alert> Alerts { get; set; } = new List<Alert>();
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
