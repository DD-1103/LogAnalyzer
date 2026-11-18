using LogAnalyzer.Web.Models;

namespace LogAnalyzer.Web.Services;

/// <summary>
/// What a user may do with an alert, by role and SOC tier (pure, unit-tested).
/// <list type="bullet">
/// <item>SOC 1 (first-line triage): works on open alerts only (New, Investigating), writes notes and escalates to SOC 2.</item>
/// <item>SOC 2 and administrators: every status change, including closing, marking false positive and reopening.</item>
/// </list>
/// An analyst without a tier is treated as SOC 1 (least privilege).
/// </summary>
public static class SocPermissions
{
    public static AnalystTier EffectiveTier(bool isAdmin, AnalystTier? tier) =>
        isAdmin ? AnalystTier.Soc2 : tier ?? AnalystTier.Soc1;

    public static bool IsOpen(AlertStatus status) => status is AlertStatus.New or AlertStatus.Investigating;

    /// <summary>Statuses the user may pick for an alert that currently has <paramref name="current"/>.</summary>
    public static IReadOnlyList<AlertStatus> AllowedStatuses(bool isAdmin, AnalystTier? tier, AlertStatus current)
    {
        if (EffectiveTier(isAdmin, tier) == AnalystTier.Soc2)
            return Enum.GetValues<AlertStatus>();
        return IsOpen(current) ? [AlertStatus.New, AlertStatus.Investigating] : [];
    }

    public static bool CanChange(bool isAdmin, AnalystTier? tier, AlertStatus current, AlertStatus next) =>
        AllowedStatuses(isAdmin, tier, current).Contains(next);

    // ---- SOC 2 escalations ----
    // An escalated alert belongs to the SOC 2 analyst who took it (Alert.AssignedToId). Only that owner changes its
    // status or verdict; everybody else can open it and add a second opinion (comment).

    public static bool IsSoc2(bool isAdmin, AnalystTier? tier) => EffectiveTier(isAdmin, tier) == AnalystTier.Soc2;

    public static bool IsEscalated(Alert alert) => alert.EscalatedAt is not null;

    public static bool IsOwner(Alert alert, string? userId) => userId is not null && alert.AssignedToId == userId;

    /// <summary>A SOC 2 analyst (or admin) can take an escalation nobody owns.</summary>
    public static bool CanClaim(bool isAdmin, AnalystTier? tier, Alert alert) =>
        IsSoc2(isAdmin, tier) && IsEscalated(alert) && alert.AssignedToId is null;

    /// <summary>The owner gives the escalation back to the queue; an administrator can do it for an absent owner.</summary>
    public static bool CanRelease(bool isAdmin, Alert alert, string? userId) =>
        IsEscalated(alert) && alert.AssignedToId is not null && (isAdmin || IsOwner(alert, userId));

    public static bool CanGiveVerdict(bool isAdmin, AnalystTier? tier, Alert alert, string? userId) =>
        IsSoc2(isAdmin, tier) && IsEscalated(alert) && IsOwner(alert, userId);

    /// <summary>Status changes from the triage form, including the escalation ownership rule.</summary>
    public static IReadOnlyList<AlertStatus> AllowedStatuses(bool isAdmin, AnalystTier? tier, Alert alert, string? userId) =>
        IsEscalated(alert)
            ? CanGiveVerdict(isAdmin, tier, alert, userId) ? Enum.GetValues<AlertStatus>() : []
            : AllowedStatuses(isAdmin, tier, alert.Status);

    public static bool CanUpdate(bool isAdmin, AnalystTier? tier, Alert alert, string? userId, AlertStatus next) =>
        AllowedStatuses(isAdmin, tier, alert, userId).Contains(next);

    /// <summary>Status that goes with a verdict: decided attacks and benign activity are closed, watching stays open.</summary>
    public static AlertStatus StatusFor(EscalationVerdict verdict) => verdict switch
    {
        EscalationVerdict.FalsePositive => AlertStatus.FalsePositive,
        EscalationVerdict.KeepMonitoring => AlertStatus.Investigating,
        _ => AlertStatus.Closed
    };

    public static string Label(EscalationVerdict verdict) => verdict switch
    {
        EscalationVerdict.Malicious => "Malicious",
        EscalationVerdict.FalsePositive => "False positive",
        EscalationVerdict.KeepMonitoring => "Keep monitoring",
        EscalationVerdict.Benign => "Benign activity",
        _ => verdict.ToString()
    };

    public static string Describe(EscalationVerdict verdict) => verdict switch
    {
        EscalationVerdict.Malicious => "Confirmed attack. The alert is closed as a true positive.",
        EscalationVerdict.FalsePositive => "Not an attack: the rule fired on legitimate traffic.",
        EscalationVerdict.KeepMonitoring => "Not decided yet. The alert stays open and the source is watched.",
        EscalationVerdict.Benign => "Real but expected or harmless activity, e.g. an authorised scanner.",
        _ => string.Empty
    };

    public enum HubState { Waiting, InProgress, Decided }

    public static HubState StateOf(Alert alert) =>
        alert.Verdict is not null ? HubState.Decided
        : alert.AssignedToId is not null ? HubState.InProgress
        : HubState.Waiting;

    /// <summary>Only SOC 1 escalates, and only open alerts that are not escalated yet.</summary>
    public static bool CanEscalate(bool isAdmin, AnalystTier? tier, Alert alert) =>
        EffectiveTier(isAdmin, tier) == AnalystTier.Soc1 && IsOpen(alert.Status) && alert.EscalatedAt is null;

    public static string Label(AnalystTier tier) => tier switch
    {
        AnalystTier.Soc1 => "SOC 1",
        AnalystTier.Soc2 => "SOC 2",
        _ => tier.ToString()
    };
}
