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
