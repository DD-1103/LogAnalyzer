using LogAnalyzer.Web.Models;

namespace LogAnalyzer.Web.ViewModels;

/// <summary>Firewall events table (Views/Shared/_FirewallEvents). IpFilterFileId links the source address to the file's event filter.</summary>
public sealed record FirewallEventsViewModel(IReadOnlyList<LogEvent> Events, int? IpFilterFileId = null);
