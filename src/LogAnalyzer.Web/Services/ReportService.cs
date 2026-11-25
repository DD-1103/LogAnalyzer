using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Helpers;
using LogAnalyzer.Web.Models;
using Microsoft.EntityFrameworkCore;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace LogAnalyzer.Web.Services;

/// <summary>Generates a PDF incident report for one log file.</summary>
public sealed class ReportService(AppDbContext db)
{
    private const int EvidenceSamplesPerAlert = 3;

    /// <summary>Alerts listed in the table and in detail; the rest is summarised (use the CSV export for all).</summary>
    public const int MaxDetailedAlerts = 200;
    private const int MaxUrlLength = 140;

    public async Task<byte[]?> BuildLogFileReportAsync(int logFileId, string generatedBy, CancellationToken ct)
    {
        var file = await db.LogFiles.AsNoTracking()
            .Include(f => f.UploadedBy)
            .FirstOrDefaultAsync(f => f.Id == logFileId, ct);
        if (file is null)
            return null;

        var alerts = (await db.Alerts.AsNoTracking()
                .Include(a => a.Rule)
                .Where(a => a.LogFileId == logFileId)
                .ToListAsync(ct))
            .OrderByDescending(a => a.Severity)
            .ThenByDescending(a => a.EventCount)
            .ToList();

        var attackingIps = alerts.Select(a => a.SourceIp).Distinct().Count();
        var hiddenAlerts = Math.Max(0, alerts.Count - MaxDetailedAlerts);
        var shown = alerts.Take(MaxDetailedAlerts).ToList();
        var shownIds = shown.Select(a => a.Id).ToList();

        var ips = shown.Select(a => a.SourceIp).Distinct().ToList();
        var ipInfo = await db.IpInfos.AsNoTracking()
            .Where(i => ips.Contains(i.Ip))
            .ToDictionaryAsync(i => i.Ip, ct);

        var reputation = (await db.IpReputations.AsNoTracking()
                .Where(r => ips.Contains(r.Ip) && r.Verdict != ThreatVerdict.Skipped && r.Verdict != ThreatVerdict.Error)
                .ToListAsync(ct))
            .GroupBy(r => r.Ip)
            .ToDictionary(g => g.Key, g => g.OrderBy(r => r.Provider).ToList());

        // First evidence lines of every shown alert in ONE query (CROSS APPLY ... TOP 3), not one query per alert.
        var samples = (await (
                from a in db.Alerts.AsNoTracking().Where(a => shownIds.Contains(a.Id))
                from e in db.AlertEvidence.Where(x => x.AlertId == a.Id)
                    .Select(x => x.LogEvent!)
                    .OrderBy(x => x.Timestamp).ThenBy(x => x.LineNumber)
                    .Take(EvidenceSamplesPerAlert)
                select new { AlertId = a.Id, Event = e }).ToListAsync(ct))
            .GroupBy(x => x.AlertId)
            .ToDictionary(g => g.Key, g => g.Select(x => x.Event).OrderBy(x => x.Timestamp).ThenBy(x => x.LineNumber).ToList());

        var maliciousEvents = await db.AlertEvidence.AsNoTracking()
            .Where(e => e.Alert!.LogFileId == logFileId)
            .Select(e => e.LogEventId)
            .Distinct()
            .CountAsync(ct);

        return Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.Margin(32);
                page.DefaultTextStyle(t => t.FontSize(9));

                page.Header().Column(col =>
                {
                    col.Item().Text("LogAnalyzer - Incident Report").FontSize(18).Bold();
                    col.Item().Text($"Log file: {file.FileName}").FontSize(11);
                    col.Item().Text($"Generated {DateTime.Now:dd/MM/yyyy HH:mm} by {generatedBy}")
                        .FontColor(Colors.Grey.Darken1);
                    col.Item().PaddingTop(6).LineHorizontal(1).LineColor(Colors.Grey.Lighten1);
                });

                page.Content().PaddingTop(10).Column(col =>
                {
                    col.Spacing(12);

                    // 1. Summary
                    col.Item().Text("1. Summary").FontSize(13).Bold();
                    col.Item().Table(t =>
                    {
                        t.ColumnsDefinition(c => { c.RelativeColumn(); c.RelativeColumn(); });
                        SummaryRow(t, "Uploaded", $"{file.UploadedAt.ToLocalTime():dd/MM/yyyy HH:mm} by {file.UploaderDisplay}");
                        SummaryRow(t, "Log kind", FirewallFormat.SourceLabel(file.Source)
                            + (LogImport.FormatLabel(file) is { } format ? $" ({format})" : ""));
                        SummaryRow(t, "File size", Format.Bytes(file.SizeBytes));
                        SummaryRow(t, "Lines parsed / failed", $"{file.ParsedLines:N0} / {file.FailedLines:N0}");
                        SummaryRow(t, file.Source == LogSource.Firewall ? "Malicious events" : "Malicious requests", $"{maliciousEvents:N0}");
                        SummaryRow(t, "Alerts", $"{alerts.Count} ({alerts.Count(a => a.Severity >= Severity.High)} high or critical)");
                        SummaryRow(t, "Attacking IPs", $"{attackingIps}");
                    });

                    // 2. Alerts overview
                    col.Item().Text("2. Alerts").FontSize(13).Bold();
                    if (alerts.Count == 0)
                    {
                        col.Item().Text("No alerts were raised for this log file.");
                    }
                    else
                    {
                        col.Item().Table(t =>
                        {
                            t.ColumnsDefinition(c =>
                            {
                                c.ConstantColumn(52);  // severity
                                c.RelativeColumn(3);   // attack
                                c.RelativeColumn(2);   // ip
                                c.ConstantColumn(40);  // country
                                c.ConstantColumn(45);  // events
                                c.RelativeColumn(2);   // time range
                                c.ConstantColumn(62);  // status
                            });
                            t.Header(h =>
                            {
                                foreach (var title in new[] { "Severity", "Attack type", "Source IP", "Ctry", "Events", "First - last seen", "Status" })
                                    HeaderCell(h.Cell(), title);
                            });
                            foreach (var a in shown)
                            {
                                ipInfo.TryGetValue(a.SourceIp, out var info);
                                BodyCell(t.Cell(), a.Severity.ToString());
                                BodyCell(t.Cell(), Format.AttackLabel(a.AttackType));
                                BodyCell(t.Cell(), a.SourceIp);
                                BodyCell(t.Cell(), info?.CountryCode ?? "-");
                                BodyCell(t.Cell(), a.EventCount.ToString("N0"));
                                BodyCell(t.Cell(), $"{a.FirstSeen:dd/MM HH:mm:ss} - {a.LastSeen:HH:mm:ss}");
                                BodyCell(t.Cell(), a.Status.ToString());
                            }
                        });
                        if (hiddenAlerts > 0)
                            col.Item().Text($"{hiddenAlerts:N0} more alert(s) with fewer events are not listed. " +
                                            "Use Alerts > Export CSV for the complete list.").Italic();
                    }

                    // 3. Details per alert
                    if (alerts.Count > 0)
                        col.Item().Text("3. Alert details and evidence").FontSize(13).Bold();

                    foreach (var a in shown)
                    {
                        ipInfo.TryGetValue(a.SourceIp, out var info);
                        col.Item().Border(0.5f).BorderColor(Colors.Grey.Lighten1).Padding(8).Column(box =>
                        {
                            box.Spacing(3);
                            box.Item().Text($"[{a.Severity}] {a.Title}").Bold();
                            box.Item().Text($"Rule: {a.Rule?.Name}  |  Events: {a.EventCount:N0}  |  Status: {a.Status}");

                            var location = info is null
                                ? "unknown"
                                : string.Join(", ", new[] { info.City, info.CountryName }.Where(s => !string.IsNullOrEmpty(s)));
                            box.Item().Text($"Source: {a.SourceIp} ({(string.IsNullOrEmpty(location) ? "unknown" : location)})");

                            if (reputation.TryGetValue(a.SourceIp, out var rep))
                                box.Item().Text("Threat intel: " + string.Join("  |  ",
                                    rep.Select(r => $"{r.Provider}: {r.Verdict} ({r.Summary})")));

                            if (a.OriginalSeverity is not null)
                                box.Item().Text(a.SeverityNote ?? $"Severity lowered from {a.OriginalSeverity}").Italic();

                            if (!string.IsNullOrWhiteSpace(a.Notes))
                                box.Item().Text($"Analyst notes: {a.Notes}").Italic();

                            box.Item().PaddingTop(3).Text("Sample evidence:").SemiBold();
                            foreach (var e in samples.GetValueOrDefault(a.Id) ?? [])
                            {
                                box.Item().Text(EvidenceLine(e)).FontFamily(Fonts.CourierNew).FontSize(7.5f);
                            }
                        });
                    }
                });

                page.Footer().AlignCenter().Text(t =>
                {
                    t.Span("Page ");
                    t.CurrentPageNumber();
                    t.Span(" of ");
                    t.TotalPages();
                });
            });
        }).GeneratePdf();
    }

    private static void SummaryRow(TableDescriptor t, string label, string value)
    {
        t.Cell().BorderBottom(0.5f).BorderColor(Colors.Grey.Lighten2).PaddingVertical(3).Text(label).SemiBold();
        t.Cell().BorderBottom(0.5f).BorderColor(Colors.Grey.Lighten2).PaddingVertical(3).Text(value);
    }

    private static void HeaderCell(IContainer cell, string text) =>
        cell.Background(Colors.Grey.Lighten3).Padding(3).Text(text).Bold();

    private static void BodyCell(IContainer cell, string text) =>
        cell.BorderBottom(0.5f).BorderColor(Colors.Grey.Lighten2).Padding(3).Text(text);

    /// <summary>One evidence line: request for web logs, connection (or message, e.g. of a failed login) for firewall logs.</summary>
    public static string EvidenceLine(LogEvent e)
    {
        string text;
        if (e.Action is not null)
        {
            var parts = new List<string> { e.Method };
            if (e.Transport is not null)
                parts.Add(e.Transport);
            parts.Add(FirewallFormat.Endpoint(e.ClientIp, e.SourcePort));
            // Events without a destination (logins, system messages) are only understandable with their message.
            if (e.DestinationIp is null && e.DestinationPort is null)
                parts.Add($" {e.Url}");
            else
                parts.Add($"-> {FirewallFormat.Endpoint(e.DestinationIp, e.DestinationPort)}");
            if ((e.ThreatName ?? e.RuleName) is { } extra)
                parts.Add($" [{extra}]");
            text = string.Join(' ', parts);
        }
        else
        {
            var url = UrlDecoder.Decode(e.Url);
            text = $"{e.Method} {url}  -> {e.StatusCode}";
        }
        if (text.Length > MaxUrlLength + 40)
            text = LogImport.Cut(text, MaxUrlLength + 40) + "...";
        // Log text is untrusted: control characters (line breaks, escape sequences) must not change the layout.
        return $"line {e.LineNumber}  {e.Timestamp:dd/MM HH:mm:ss}  {AuditLog.Clean(text)}";
    }
}
