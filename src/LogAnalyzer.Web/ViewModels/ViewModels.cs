using System.ComponentModel.DataAnnotations;
using LogAnalyzer.Web.Models;

namespace LogAnalyzer.Web.ViewModels;

public class LoginViewModel
{
    [Required, EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required, DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    [Display(Name = "Remember me")]
    public bool RememberMe { get; set; }

    public string? ReturnUrl { get; set; }
}

public class DashboardViewModel
{
    public int? LogFileId { get; set; }
    public List<LogFile> Files { get; set; } = [];

    public int LogFiles { get; set; }
    public long Events { get; set; }
    public int OpenAlerts { get; set; }
    public int OpenHighOrCritical { get; set; }
    public int EnabledRules { get; set; }
    public bool GeoIpAvailable { get; set; }
    public string? GeoIpSource { get; set; }

    public List<string> HourLabels { get; set; } = [];
    public List<int> HourTotal { get; set; } = [];
    public List<int> HourMalicious { get; set; } = [];

    public List<NameCount> BySeverity { get; set; } = [];
    public List<NameCount> ByAttackType { get; set; } = [];
    public List<TopIp> TopIps { get; set; } = [];
    public List<MapPoint> MapPoints { get; set; } = [];
    public List<Alert> RecentAlerts { get; set; } = [];
}

public record NameCount(string Name, int Count);

public record TopIp(string Ip, string? CountryCode, string? Country, string? City, int? AbuseScore,
    int Alerts, int Events, Severity MaxSeverity, string AttackTypes, double? Latitude, double? Longitude,
    List<IpReputation> Reputation);

public record MapPoint(string Ip, double Lat, double Lon, string? Country, string? City,
    int Alerts, int Events, string Severity);

public class LogFileDetailsViewModel
{
    public required LogFile File { get; set; }
    public List<LogEvent> Events { get; set; } = [];
    public int Page { get; set; }
    public int TotalPages { get; set; }
    public int FilteredCount { get; set; }
    public string? Ip { get; set; }
    public int? Status { get; set; }
    public int AlertCount { get; set; }
}

public class EvaluationViewModel
{
    public required LogFile File { get; set; }
    public string? LabelsFileName { get; set; }
    public LogAnalyzer.Web.Services.EvaluationResult? Result { get; set; }
}

public class AlertListViewModel
{
    public List<Alert> Alerts { get; set; } = [];
    public AlertStatus? Status { get; set; }
    public Severity? Severity { get; set; }
    public AttackType? AttackType { get; set; }
    public string? Ip { get; set; }
    public int? LogFileId { get; set; }
    public int Page { get; set; }
    public int TotalPages { get; set; }
    public int TotalCount { get; set; }
    public DateTime? PreviousSeenAt { get; set; }

    public bool IsNewSinceLastVisit(Alert a) => PreviousSeenAt is null || a.CreatedAt > PreviousSeenAt;
}

public class AlertDetailsViewModel
{
    public required Alert Alert { get; set; }
    public List<LogEvent> Evidence { get; set; } = [];
    public int EvidenceShown { get; set; }
    public IpInfo? IpInfo { get; set; }
    public IReadOnlyList<LogAnalyzer.Web.Services.IThreatIntelProvider> Providers { get; set; } = [];
    public Dictionary<string, IpReputation> Reputation { get; set; } = [];
}

public class AlertUpdateModel
{
    public AlertStatus Status { get; set; }

    [StringLength(4000)]
    public string? Notes { get; set; }
}

// ---- Threat intelligence ----

public record ProviderStatus(LogAnalyzer.Web.Services.IThreatIntelProvider Provider, Dictionary<ThreatVerdict, int> Verdicts)
{
    public int Total => Verdicts.Values.Sum();
}

public record SeverityChange(Severity From, Severity To, int Count);

public class ThreatIntelIndexViewModel
{
    public List<ProviderStatus> Providers { get; set; } = [];
    public int TotalAlerts { get; set; }
    public List<SeverityChange> Downgrades { get; set; } = [];
    public List<IpReputation> Recent { get; set; } = [];
}

public class ThreatIntelProviderViewModel
{
    public required LogAnalyzer.Web.Services.IThreatIntelProvider Provider { get; set; }
    public List<IpReputation> Results { get; set; } = [];
    public int Page { get; set; }
    public int TotalPages { get; set; }
    public int TotalCount { get; set; }
}

public class ThreatIntelLookupViewModel
{
    public IReadOnlyList<LogAnalyzer.Web.Services.IThreatIntelProvider> Providers { get; set; } = [];
    public string? Ip { get; set; }
    public string? Error { get; set; }
    public bool IsPublic { get; set; }
    public Dictionary<string, IpReputation> Results { get; set; } = [];
    public IpInfo? IpInfo { get; set; }
    public int AlertCount { get; set; }
    public int EventCount { get; set; }
}

public record ReputationCardModel(LogAnalyzer.Web.Services.IThreatIntelProvider Provider, IpReputation? Result,
    string Ip, bool IsPublic, string? ReturnUrl);

// ---- Rule management ----

public record LogFileOption(int Id, string FileName, int Lines);

public class RuleFormModel
{
    public int? Id { get; set; }

    [Required, StringLength(150)]
    public string Name { get; set; } = string.Empty;

    [StringLength(1000)]
    public string? Description { get; set; }

    [Display(Name = "Attack type")]
    public AttackType AttackType { get; set; }
    public Severity Severity { get; set; }
    public RuleKind Kind { get; set; }

    // Signature
    public RuleField Field { get; set; } = RuleField.Url;

    [StringLength(2000)]
    public string? Pattern { get; set; }

    // Threshold (and "minimum requests" for anomaly rules)
    [Range(1, 1_000_000)]
    public int? Threshold { get; set; }

    [Display(Name = "Window (seconds)"), Range(1, 86_400)]
    public int? WindowSeconds { get; set; }

    [Display(Name = "HTTP method"), StringLength(16), RegularExpression("^[A-Za-z]+$", ErrorMessage = "Method must be letters only, e.g. POST.")]
    public string? MethodFilter { get; set; }

    [Display(Name = "Path pattern"), StringLength(500)]
    public string? PathPattern { get; set; }

    [Display(Name = "Status code"), Range(100, 599)]
    public int? StatusFilter { get; set; }

    // Anomaly
    [Display(Name = "Score threshold"), Range(0.5, 1.0)]
    public double? ScoreThreshold { get; set; }

    [Display(Name = "Enabled")]
    public bool IsEnabled { get; set; } = true;

    // Rule tester
    [Display(Name = "Test against")]
    public int? TestLogFileId { get; set; }
    public List<LogFileOption> LogFiles { get; set; } = [];
    public LogAnalyzer.Web.Services.RuleTestResult? TestResult { get; set; }

    /// <summary>Clears the fields that do not apply to the chosen kind, and trims text.</summary>
    public void Normalize()
    {
        Name = (Name ?? string.Empty).Trim();
        Description = string.IsNullOrWhiteSpace(Description) ? null : Description.Trim();
        Pattern = string.IsNullOrWhiteSpace(Pattern) ? null : Pattern;
        PathPattern = string.IsNullOrWhiteSpace(PathPattern) ? null : PathPattern;
        MethodFilter = string.IsNullOrWhiteSpace(MethodFilter) ? null : MethodFilter.Trim().ToUpperInvariant();

        if (Kind != RuleKind.Signature)
            Pattern = null;
        if (Kind != RuleKind.Threshold)
        {
            WindowSeconds = null;
            MethodFilter = null;
            PathPattern = null;
            StatusFilter = null;
        }
        if (Kind == RuleKind.Signature)
            Threshold = null;
        if (Kind != RuleKind.Anomaly)
            ScoreThreshold = null;
    }

    public DetectionRule ToRule()
    {
        var rule = new DetectionRule { Id = Id ?? 0 };
        ApplyTo(rule);
        return rule;
    }

    public void ApplyTo(DetectionRule r)
    {
        r.Name = Name;
        r.Description = Description;
        r.AttackType = AttackType;
        r.Severity = Severity;
        r.Kind = Kind;
        r.Field = Field;
        r.Pattern = Pattern;
        r.Threshold = Threshold;
        r.WindowSeconds = WindowSeconds;
        r.MethodFilter = MethodFilter;
        r.PathPattern = PathPattern;
        r.StatusFilter = StatusFilter;
        r.ScoreThreshold = ScoreThreshold;
        r.IsEnabled = IsEnabled;
    }

    public static RuleFormModel From(DetectionRule r) => new()
    {
        Id = r.Id,
        Name = r.Name,
        Description = r.Description,
        AttackType = r.AttackType,
        Severity = r.Severity,
        Kind = r.Kind,
        Field = r.Field,
        Pattern = r.Pattern,
        Threshold = r.Threshold,
        WindowSeconds = r.WindowSeconds,
        MethodFilter = r.MethodFilter,
        PathPattern = r.PathPattern,
        StatusFilter = r.StatusFilter,
        ScoreThreshold = r.ScoreThreshold,
        IsEnabled = r.IsEnabled
    };
}

// ---- User management ----

public record UserRow(AppUser User, string Role, bool IsLockedOut, bool IsSelf);

public class CreateUserModel
{
    [Required, EmailAddress, StringLength(256)]
    public string Email { get; set; } = string.Empty;

    [Required, StringLength(150), Display(Name = "Full name")]
    public string FullName { get; set; } = string.Empty;

    [Required]
    public string Role { get; set; } = LogAnalyzer.Web.Data.Roles.Analyst;

    [Required, DataType(DataType.Password), StringLength(128, MinimumLength = 10)]
    public string Password { get; set; } = string.Empty;

    [Required, DataType(DataType.Password), Compare(nameof(Password)), Display(Name = "Confirm password")]
    public string ConfirmPassword { get; set; } = string.Empty;
}

public class ChangePasswordModel
{
    [Required, DataType(DataType.Password), Display(Name = "Current password")]
    public string CurrentPassword { get; set; } = string.Empty;

    [Required, DataType(DataType.Password), StringLength(128, MinimumLength = 10), Display(Name = "New password")]
    public string NewPassword { get; set; } = string.Empty;

    [Required, DataType(DataType.Password), Compare(nameof(NewPassword)), Display(Name = "Confirm new password")]
    public string ConfirmPassword { get; set; } = string.Empty;
}

public class AuditViewModel
{
    public List<AuditEntry> Entries { get; set; } = [];
    public List<string> Actions { get; set; } = [];
    public string? User { get; set; }
    public string? Action { get; set; }
    public int Page { get; set; }
    public int TotalPages { get; set; }
    public int TotalCount { get; set; }
}
