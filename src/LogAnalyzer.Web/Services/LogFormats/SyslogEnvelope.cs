using System.Text.RegularExpressions;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>
/// The syslog wrapper most firewalls (or the collector in front of them) put around their own message:
/// <list type="bullet">
/// <item>RFC 5424: <c>&lt;134&gt;1 2026-11-21T10:00:00Z fw01 app 123 MSGID [sd] message</c></item>
/// <item>RFC 3164 / BSD: <c>&lt;134&gt;Nov 21 10:00:00 fw01 tag[123]: message</c>, also with a year
/// (<c>Nov 21 2026 10:00:00</c>, Cisco) or an ISO time stamp (rsyslog high precision)</item>
/// <item>no wrapper at all (file written by the device): the whole line is the message.</item>
/// </list>
/// Parsers call <see cref="Parse"/> and then read their vendor message from <see cref="Message"/>; when the vendor
/// message has its own date (most do) that one should win, <see cref="Timestamp"/> is the fallback.
/// </summary>
public sealed partial record SyslogEnvelope(int? Priority, DateTimeOffset? Timestamp, string? Host, string? AppName, string Message, string? StructuredData)
{
    /// <summary>RFC 5424 MSGID (e.g. Junos "RT_FLOW_SESSION_DENY"); null for BSD syslog or "-".</summary>
    public string? MsgId { get; init; }

    // <PRI>1 TIMESTAMP HOST APP PROCID MSGID (SD|-) MSG
    [GeneratedRegex(@"^<(?<pri>\d{1,3})>1 (?<ts>\S+) (?<host>\S+) (?<app>\S+) (?<proc>\S+) (?<msgid>\S+) (?<rest>.*)$", RegexOptions.CultureInvariant)]
    private static partial Regex Rfc5424();

    // [<PRI>]TIMESTAMP HOST [TAG[pid]:] MSG ; TIMESTAMP = "Nov 21 10:00:00" | "Nov 21 2026 10:00:00" | ISO 8601
    [GeneratedRegex(
        @"^(?:<(?<pri>\d{1,3})>:?)?\s*(?<ts>[A-Z][a-z]{2} {1,2}\d{1,2}(?: \d{4})? \d{2}:\d{2}:\d{2}(?:\.\d+)?|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)(?: (?<zone>UTC|GMT))?\s*:?\s+(?<rest>.*)$",
        RegexOptions.CultureInvariant)]
    private static partial Regex Rfc3164();

    // Host followed by an optional "tag[pid]:" or "tag:" - the host must not look like a vendor message start.
    [GeneratedRegex(@"^(?<host>[A-Za-z0-9][\w.\-:]*)\s+(?<rest>.*)$", RegexOptions.CultureInvariant)]
    private static partial Regex HostThenRest();

    [GeneratedRegex(@"^(?<tag>[A-Za-z][\w\-./]{0,47})(?:\[(?<pid>\d+)\])?:\s?(?<msg>.*)$", RegexOptions.CultureInvariant)]
    private static partial Regex Tag();

    [GeneratedRegex(@"^<(?<pri>\d{1,3})>(?<rest>.*)$", RegexOptions.CultureInvariant)]
    private static partial Regex PriOnly();

    public static SyslogEnvelope Parse(string line, LogParseContext context)
    {
        var m = Rfc5424().Match(line);
        if (m.Success)
        {
            var rest = m.Groups["rest"].Value;
            string? sd = null;
            if (rest.StartsWith("- ", StringComparison.Ordinal) || rest == "-")
                rest = rest.Length > 2 ? rest[2..] : "";
            else if (rest.StartsWith('['))
            {
                var end = StructuredDataEnd(rest);
                sd = rest[..end];
                rest = end < rest.Length ? rest[end..].TrimStart() : "";
            }
            if (rest.StartsWith('﻿'))
                rest = rest[1..];
            DateTimeOffset? ts = LogTime.TryParse(m.Groups["ts"].Value, context, out var t) ? t : null;
            var app = m.Groups["app"].Value;
            return new SyslogEnvelope(int.Parse(m.Groups["pri"].Value), ts, Nil(m.Groups["host"].Value), Nil(app), rest, sd)
            {
                MsgId = Nil(m.Groups["msgid"].Value)
            };
        }

        m = Rfc3164().Match(line);
        if (m.Success)
        {
            int? pri = m.Groups["pri"].Success ? int.Parse(m.Groups["pri"].Value) : null;
            // "Nov 21 10:00:00 UTC" (Cisco ASA / FTD): the zone word wins over the file's default offset.
            var tsContext = m.Groups["zone"].Success ? context with { DefaultOffset = TimeSpan.Zero } : context;
            DateTimeOffset? ts = LogTime.TryParse(m.Groups["ts"].Value, tsContext, out var t) ? t : null;
            var rest = m.Groups["rest"].Value;
            string? host = null, app = null;

            // "fw01 kernel: ..." / "fw01 %ASA-4-106023: ..." / "kernel: ..." (no host)
            var tagFirst = Tag().Match(rest);
            if (!tagFirst.Success || rest.StartsWith('%'))
            {
                var h = HostThenRest().Match(rest);
                if (h.Success && !LooksLikeMessageStart(h.Groups["host"].Value))
                {
                    host = h.Groups["host"].Value;
                    rest = h.Groups["rest"].Value;
                }
            }
            var tag = Tag().Match(rest);
            if (tag.Success && !rest.StartsWith('%') && !rest.StartsWith("CEF:", StringComparison.Ordinal)
                && !rest.StartsWith("LEEF:", StringComparison.Ordinal))
            {
                app = tag.Groups["tag"].Value;
                rest = tag.Groups["msg"].Value;
            }
            return new SyslogEnvelope(pri, ts, host, app, rest, null);
        }

        m = PriOnly().Match(line);
        if (m.Success)
            return new SyslogEnvelope(int.Parse(m.Groups["pri"].Value), null, null, null, m.Groups["rest"].Value.TrimStart(), null);

        return new SyslogEnvelope(null, null, null, null, line, null);
    }

    private static string? Nil(string v) => v == "-" ? null : v;

    // key=value or CEF/LEEF or %ASA- right after the time stamp means there is no host name.
    private static bool LooksLikeMessageStart(string token) =>
        token.Contains('=') || token.StartsWith("CEF", StringComparison.Ordinal) || token.StartsWith("LEEF", StringComparison.Ordinal);

    /// <summary>End index (exclusive) of one or more "[id k="v" ...]" elements; quotes may contain escaped "]".</summary>
    private static int StructuredDataEnd(string s)
    {
        var i = 0;
        while (i < s.Length && s[i] == '[')
        {
            var inQuotes = false;
            for (i++; i < s.Length; i++)
            {
                var c = s[i];
                if (c == '\\' && i + 1 < s.Length) { i++; continue; }
                if (c == '"') inQuotes = !inQuotes;
                else if (c == ']' && !inQuotes) { i++; break; }
            }
        }
        return Math.Min(i, s.Length);
    }
}
