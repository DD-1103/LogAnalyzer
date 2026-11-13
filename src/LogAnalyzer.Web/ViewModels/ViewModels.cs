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
    int Alerts, int Events, Severity MaxSeverity, string AttackTypes, double? Latitude, double? Longitude);

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
}

public class AlertUpdateModel
{
    public AlertStatus Status { get; set; }

    [StringLength(4000)]
    public string? Notes { get; set; }
}
