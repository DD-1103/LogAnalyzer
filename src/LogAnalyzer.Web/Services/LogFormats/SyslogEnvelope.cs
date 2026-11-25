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
    [GeneratedRegex(@"^<(?<pri>[0-9]{1,3})>1 (?<ts>\S+) (?<host>\S+) (?<app>\S+) (?<proc>\S+) (?<msgid>\S+) (?<rest>.*)\z", RegexOptions.CultureInvariant | RegexOptions.Singleline)]
    private static partial Regex Rfc5424();

    // [<PRI>]TIMESTAMP HOST [TAG[pid]:] MSG ; TIMESTAMP = "Nov 21 10:00:00" | "Nov 21 2026 10:00:00" |
    // "Nov 21 10:00:00 2026" (Zyxel) | ISO 8601 (with "T" or a space), then an optional zone word (Cisco)
    [GeneratedRegex(
        @"^(?:<(?<pri>[0-9]{1,3})>:?)?\s*(?<ts>[A-Z][a-z]{2} {1,2}[0-9]{1,2}(?: [0-9]{4})? [0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?|[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)(?: (?<year>20[0-9]{2})(?= ))?(?: (?<zone>UTC|GMT|WES?T|BST|CES?T|EES?T|MSK|[ECMP][SD]T)(?=[ :]))?\s*:?\s+(?<rest>.*)\z",
        RegexOptions.CultureInvariant | RegexOptions.Singleline)]
    private static partial Regex Rfc3164();

    // Host followed by an optional "tag[pid]:" or "tag:" - the host must not look like a vendor message start.
    [GeneratedRegex(@"^(?<host>[A-Za-z0-9][\w.\-:]*)\s+(?<rest>.*)\z", RegexOptions.CultureInvariant | RegexOptions.Singleline)]
    private static partial Regex HostThenRest();

    [GeneratedRegex(@"^(?<tag>[A-Za-z][\w\-./]{0,47})(?:\[(?<pid>[0-9]+)\])?:\s?(?<msg>.*)\z", RegexOptions.CultureInvariant | RegexOptions.Singleline)]
    private static partial Regex Tag();

    [GeneratedRegex(@"^<(?<pri>[0-9]{1,3})>(?<rest>.*)\z", RegexOptions.CultureInvariant | RegexOptions.Singleline)]
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
            // "Nov 21 10:00:00 UTC" / "CEST" (Cisco ASA / FTD): the zone word wins over the file's default offset.
            var tsContext = m.Groups["zone"].Success && FirewallTime.TryOffset(m.Groups["zone"].Value, out var zone)
                ? context with { DefaultOffset = zone } : context;
            var tsText = m.Groups["ts"].Value;
            if (m.Groups["year"].Success && char.IsAsciiLetter(tsText[0]))
                tsText = tsText.Insert(tsText.LastIndexOf(' '), " " + m.Groups["year"].Value);
            DateTimeOffset? ts = LogTime.TryParse(tsText, tsContext, out var t) ? t : null;
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

    /// <summary>
    /// Programs that are not a firewall but write attacker-controlled text (user names, URLs) to the same syslog. A
    /// firewall record found inside such a message is forged ("Invalid user %ASA-4-106023: Deny ...").
    /// </summary>
    private static readonly HashSet<string> OtherPrograms = new(StringComparer.OrdinalIgnoreCase)
    {
        "sshd", "sshd-session", "dropbear", "sudo", "su", "login", "cron", "crond", "systemd", "systemd-logind", "nginx", "httpd",
        "apache", "apache2", "lighttpd", "caddy", "haproxy", "squid", "traefik", "postfix", "dovecot", "exim", "sendmail", "named",
        "dnsmasq", "unbound", "dhcpd", "mysqld", "mariadbd", "postgres", "vsftpd", "proftpd", "pure-ftpd", "telnetd", "in.telnetd",
        "xinetd", "smbd", "fail2ban", "audit", "auditd", "openvpn", "pppd", "radiusd", "freeradius", "php", "php-fpm", "tomcat"
    };

    /// <summary>True when the line was written by one of the <see cref="OtherPrograms"/>.</summary>
    public bool FromOtherProgram =>
        AppName is { } app && (OtherPrograms.Contains(app) || app.StartsWith("postfix/", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// True when a vendor record that starts at <paramref name="index"/> of <see cref="Message"/> is the message itself:
    /// only a few header words (second time stamp, host, serial number) and no quotes in front of it, and not written
    /// by another program. Guards against records smuggled in through a user name or URL.
    /// </summary>
    public bool RecordStartsAt(int index, int maxWords = 6)
    {
        if (index < 0 || index > 200 || FromOtherProgram)
            return false;
        // after a program tag the record follows (nearly) directly: "host CiscoASA[999]: %ASA-..."
        var limit = AppName is null ? maxWords : Math.Min(maxWords, 2);
        var words = 0;
        var inWord = false;
        for (var i = 0; i < Math.Min(index, Message.Length); i++)
        {
            var c = Message[i];
            if (c is '"' or '\'' or '=')
                return false;
            if (char.IsWhiteSpace(c))
                inWord = false;
            else if (!inWord)
            {
                inWord = true;
                if (++words > limit)
                    return false;
            }
        }
        return true;
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
