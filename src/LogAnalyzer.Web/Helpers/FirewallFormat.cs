using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services.LogFormats;

namespace LogAnalyzer.Web.Helpers;

/// <summary>Display helpers for firewall events and log formats.</summary>
public static class FirewallFormat
{
    /// <summary>Badge class of a firewall decision: allowed green, blocked red, detected-only orange.</summary>
    public static string ActionBadge(FirewallAction? action) => action switch
    {
        FirewallAction.Allow => "text-bg-success",
        FirewallAction.Deny or FirewallAction.Drop or FirewallAction.Reject => "text-bg-danger",
        FirewallAction.Alert => "text-bg-warning",
        _ => "text-bg-secondary"
    };

    public static string ActionLabel(FirewallAction? action) => action switch
    {
        null or FirewallAction.Unknown => "Event",
        _ => action.Value.ToString()
    };

    /// <summary>"203.0.113.5:51234", "[2001:db8::5]:443" or just the address; "-" when unknown.</summary>
    public static string Endpoint(string? ip, int? port)
    {
        if (string.IsNullOrEmpty(ip) || ip == "-")
            return port is null ? "-" : ":" + port;
        if (port is null)
            return ip;
        return ip.Contains(':') ? $"[{ip}]:{port}" : $"{ip}:{port}";
    }

    public static string SourceLabel(LogSource source) => source switch
    {
        LogSource.Firewall => "Firewall log",
        _ => "Web access log"
    };

    public static string SourceIcon(LogSource source) => source switch
    {
        LogSource.Firewall => "bi-bricks",
        _ => "bi-globe2"
    };

    /// <summary>Formats offered on the upload page, web first, then firewalls by name.</summary>
    public static IEnumerable<IGrouping<LogSource, ILogFormat>> UploadChoices() =>
        LogFormatRegistry.All.OrderBy(f => f.Source).ThenBy(f => f.DisplayName, StringComparer.OrdinalIgnoreCase).GroupBy(f => f.Source);
}
