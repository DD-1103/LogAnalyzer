using System.Globalization;
using System.Text.RegularExpressions;
using LogAnalyzer.Web.Models;
using static LogAnalyzer.Web.Services.LogFormats.PositionalFormatHelpers;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>
/// Cisco ASA, Firepower Threat Defense and PIX syslog ("Cisco Secure Firewall ASA Series Syslog Messages"):
/// <c>%ASA-4-106023: Deny tcp src outside:203.0.113.5/51234 dst inside:10.0.0.5/22 by access-group "OUTSIDE_IN" [0x0, 0x0]</c>,
/// with or without a syslog header or the device's own "Nov 21 2026 10:00:00 fw01 :" / "&lt;166&gt;:Nov 21 10:00:00 UTC:"
/// prefix. Security-relevant message ids (denies, connections, ICMP, threat detection, IP audit / IPS, AAA and VPN
/// logins, FTD 430001-430003 events) become events; every other %ASA- / %FTD- message is a valid but skipped line.
/// </summary>
public sealed partial class CiscoAsaFormat : ILogFormat
{
    public string Id => "cisco-asa";
    public string DisplayName => "Cisco ASA / FTD";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 100;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    // %ASA-4-106023: / %FTD-session-6-302013: (the optional word is written by some FTD versions)
    [GeneratedRegex(@"^%(?<fam>ASA|FTD|PIX|FWSM)-(?:[a-z]{1,16}-)?(?<lvl>[0-7])-(?<id>\d{6}):?\s?", RegexOptions.CultureInvariant)]
    private static partial Regex TagRegex();

    // 106100: access-list OUTSIDE_IN denied tcp outside/203.0.113.5(51234) -> inside/10.0.0.5(22) hit-cnt 1 first hit [...]
    [GeneratedRegex(@"^access-list (?<acl>\S+) (?<act>permitted|denied|est-allowed) (?<p>\w+) (?<si>[^/\s]+)/(?<s>[^(\s]+)\((?<sp>\d+)\)(?: \([^)]*\))? -> (?<di>[^/\s]+)/(?<d>[^(\s]+)\((?<dp>\d+)\)", RegexOptions.CultureInvariant)]
    private static partial Regex AccessList();

    // 302013 / 302015: Built inbound TCP connection 123 for outside:a/p (a/p) to inside:b/p (b/p)
    [GeneratedRegex(@"^Built (?<dir>inbound|outbound) (?<p>TCP|UDP|SCTP) connection (?<id>\d+) for (?<a>\S+) (?:\([^)]*\) ){0,3}to (?<b>\S+)", RegexOptions.CultureInvariant)]
    private static partial Regex Built();

    // 302020 / 302021: Built inbound ICMP connection for faddr 203.0.113.5/0 gaddr 10.0.0.5/0 laddr 10.0.0.5/0 type 8 code 0
    //                  Teardown ICMP connection for faddr ... gaddr ... laddr ...
    [GeneratedRegex(@"^(?<what>Built|Teardown) (?:(?<dir>inbound|outbound) )?(?<p>ICMP|ICMPv6) connection for faddr (?<f>[0-9A-Fa-f:.]+)/\d+(?:\(\S*\))? gaddr \S+ laddr (?<l>[0-9A-Fa-f:.]+)/\d+", RegexOptions.CultureInvariant)]
    private static partial Regex IcmpConnection();

    // 302014 / 302016: Teardown TCP connection 123 for outside:a/p to inside:b/p duration 0:00:05 bytes 1234 TCP FINs
    [GeneratedRegex(@"^Teardown (?<p>TCP|UDP|SCTP) connection (?<id>\d+) for (?<a>\S+) (?:\([^)]*\) ){0,3}to (?<b>\S+) (?:\([^)]*\) ){0,3}duration (?<dur>\S+) bytes (?<bytes>\d+)", RegexOptions.CultureInvariant)]
    private static partial Regex Teardown();

    // 4000nn: IPS:2004 ICMP Echo Request from 203.0.113.5 to 10.0.0.5 on interface outside
    [GeneratedRegex(@"^IPS:(?<sig>\d+) (?<name>[^\r\n]{1,200}?) from (?<s>[0-9A-Fa-f:.]+) to (?<d>[0-9A-Fa-f:.]+) on interface (?<if>\S+)", RegexOptions.CultureInvariant)]
    private static partial Regex Ips();

    // Group <g> User <u> IP <ip> ... (VPN / WebVPN messages)
    [GeneratedRegex(@"^Group <(?<g>[^>]*)> User <(?<u>[^>]*)> IP <(?<ip>[0-9A-Fa-f:.]+)> ?(?<rest>.*)$", RegexOptions.CultureInvariant)]
    private static partial Regex GroupUserIp();

    private static readonly Dictionary<string, int> Services = new(StringComparer.OrdinalIgnoreCase)
    {
        ["ftp"] = 21, ["ssh"] = 22, ["telnet"] = 23, ["smtp"] = 25, ["domain"] = 53, ["www"] = 80, ["http"] = 80,
        ["pop3"] = 110, ["netbios-ssn"] = 139, ["snmp"] = 161, ["ldap"] = 389, ["https"] = 443, ["sqlnet"] = 1521
    };

    private sealed class Parser(LogParseContext context) : ILineParser
    {
        public ParseOutcome Parse(string line, out ParsedLine? result)
        {
            result = null;
            var idx = FindTag(line);
            if (idx < 0)
                return ParseOutcome.Failed;
            var tag = TagRegex().Match(line, idx, Math.Min(40, line.Length - idx));
            if (!tag.Success)
                return ParseOutcome.Failed;
            var id = int.Parse(tag.Groups["id"].Value, CultureInfo.InvariantCulture);
            var msg = line[(idx + tag.Length)..].Trim();

            var outcome = Dispatch(id, msg, out var ev);
            if (outcome != ParseOutcome.Parsed || ev is null)
                return outcome;

            var prefix = line[..idx];
            if (!TryPrefixTime(prefix, out var ts, out var host))
                return ParseOutcome.Failed;
            result = ParsedLine.Network(ev.Src, ts, ev.Action, Short(CleanMessage(msg)), ev.Dst, ev.SrcPort, ev.DstPort,
                ev.Proto, ev.Type, ev.Rule, ev.Threat, host, ev.Bytes);
            return ParseOutcome.Parsed;
        }

        private static int FindTag(string line)
        {
            var i = line.IndexOf('%');
            while (i >= 0 && i + 5 < line.Length)
            {
                var s = line.AsSpan(i + 1);
                if (s.StartsWith("ASA-") || s.StartsWith("FTD-") || s.StartsWith("PIX-") || s.StartsWith("FWSM-"))
                    return i;
                i = line.IndexOf('%', i + 1);
            }
            return -1;
        }

        /// <summary>Time stamp from the syslog header or the ASA's own "Nov 21 2026 10:00:00" / ":Nov 21 10:00:00 UTC:".</summary>
        private bool TryPrefixTime(string prefix, out DateTimeOffset ts, out string? host)
        {
            host = null;
            ts = default;
            var p = prefix.Trim();
            if (p.Length == 0)
                return false;
            var utc = p.Contains(" UTC", StringComparison.Ordinal) || p.Contains(" GMT", StringComparison.Ordinal);
            var env = SyslogEnvelope.Parse(p + " %", context);
            if (env.Timestamp is { } t)
            {
                ts = utc ? new DateTimeOffset(t.DateTime, TimeSpan.Zero) : t;
                host = env.Host;
                return true;
            }
            // "<166>:Nov 21 10:00:00 UTC:" - strip the priority, colons and the zone word
            var s = p;
            if (s.StartsWith('<'))
            {
                var gt = s.IndexOf('>');
                if (gt > 0)
                    s = s[(gt + 1)..];
            }
            s = s.Trim().Trim(':').Trim();
            foreach (var zone in new[] { " UTC", " GMT" })
                if (s.EndsWith(zone, StringComparison.Ordinal))
                    s = s[..^zone.Length];
            if (!LogTime.TryParse(s, context, out var parsed))
                return false;
            ts = utc ? new DateTimeOffset(parsed.DateTime, TimeSpan.Zero) : parsed;
            return true;
        }

        private static string CleanMessage(string msg)
        {
            // drop the ACL hash codes " [0x0, 0x0]"
            var i = msg.LastIndexOf(" [0x", StringComparison.Ordinal);
            return i > 0 && msg.EndsWith(']') ? msg[..i] : msg;
        }
    }

    private sealed record Ev(string? Src, string? Dst, int? SrcPort, int? DstPort, string? Proto, FirewallAction Action,
        string Type, string? Rule = null, string? Threat = null, long? Bytes = null);

    private static ParseOutcome Dispatch(int id, string msg, out Ev? ev)
    {
        ev = null;
        switch (id)
        {
            case 106001:   // Inbound TCP connection denied from a/p to b/p flags SYN on interface outside
                return FromTo(msg, Word(msg, 1), FirewallAction.Deny, "traffic", out ev);
            case 106002:   // tcp Connection denied by outbound list ACL src a dest b
            {
                var acl = Token(msg, "outbound list ");
                var ok = SplitAny(Token(msg, " src "), out var s, out var sp) & SplitAny(Token(msg, " dest "), out var d, out var dp);
                if (!ok) return Fail(out ev);
                ev = new Ev(s, d, sp, dp, Transport(Word(msg, 0)), FirewallAction.Deny, "traffic", acl);
                return ParseOutcome.Parsed;
            }
            case 106006:   // Deny inbound UDP from a/p to b/p on interface outside
            case 106007:   // Deny inbound UDP from a/p to b/p due to DNS Query
                return FromTo(msg, Word(msg, 2), FirewallAction.Deny, "traffic", out ev);
            case 106010:   // Deny inbound tcp src outside:a/p dst inside:b/p
            case 106014:   // Deny inbound icmp src outside:a dst inside:b (type 8, code 0)
                return SrcDst(msg, Word(msg, 2), FirewallAction.Deny, "traffic", null, out ev);
            case 106015:   // Deny TCP (no connection) from a/p to b/p flags RST on interface outside
                return FromTo(msg, Word(msg, 1), FirewallAction.Deny, "traffic", out ev);
            case 106017:   // Deny IP due to Land Attack from a to b
                return FromTo(msg, "ip", FirewallAction.Deny, "threat", out ev, "Land attack");
            case 106021:   // Deny TCP reverse path check from a to b on interface outside
                return FromTo(msg, Word(msg, 1), FirewallAction.Deny, "threat", out ev, "Reverse path check failed (spoofed source)");
            case 106023:   // Deny tcp src outside:a/p dst inside:b/p by access-group "OUTSIDE_IN" [0x0, 0x0]
                return SrcDst(msg, Word(msg, 1), FirewallAction.Deny, "traffic", Quoted(msg, "access-group "), out ev);
            case 106100:
            {
                var m = AccessList().Match(msg);
                if (!m.Success || !IsIp(m.Groups["s"].Value) || !IsIp(m.Groups["d"].Value))
                    return Fail(out ev);
                var proto = Transport(m.Groups["p"].Value);
                var ports = proto is "tcp" or "udp" or "sctp";
                var act = m.Groups["act"].Value == "denied" ? FirewallAction.Deny : FirewallAction.Allow;
                ev = new Ev(m.Groups["s"].Value, m.Groups["d"].Value, ports ? Port(m.Groups["sp"].Value) : null,
                    ports ? Port(m.Groups["dp"].Value) : null, proto, act, "traffic", m.Groups["acl"].Value);
                return ParseOutcome.Parsed;
            }
            case 302013:
            case 302015:
            {
                var m = Built().Match(msg);
                if (!m.Success || !TrySplitSlash(m.Groups["a"].Value, out var a, out var ap) || !TrySplitSlash(m.Groups["b"].Value, out var b, out var bp))
                    return Fail(out ev);
                // "for" = the lower-security side; outbound = initiated from the "to" side
                ev = m.Groups["dir"].Value == "inbound"
                    ? new Ev(a, b, ap, bp, Transport(m.Groups["p"].Value), FirewallAction.Allow, "traffic")
                    : new Ev(b, a, bp, ap, Transport(m.Groups["p"].Value), FirewallAction.Allow, "traffic");
                return ParseOutcome.Parsed;
            }
            case 302020:
            case 302021:
            {
                var m = IcmpConnection().Match(msg);
                if (!m.Success || !IsIp(m.Groups["f"].Value) || !IsIp(m.Groups["l"].Value))
                    return Fail(out ev);
                // faddr = the outside (foreign) host; teardown lines carry no direction, the foreign side is taken as source
                var outbound = m.Groups["dir"].Value == "outbound";
                var proto = m.Groups["p"].Value == "ICMPv6" ? "ipv6-icmp" : "icmp";
                ev = outbound
                    ? new Ev(m.Groups["l"].Value, m.Groups["f"].Value, null, null, proto, FirewallAction.Allow, "traffic")
                    : new Ev(m.Groups["f"].Value, m.Groups["l"].Value, null, null, proto, FirewallAction.Allow, "traffic");
                return ParseOutcome.Parsed;
            }
            case 302014:
            case 302016:
            {
                var m = Teardown().Match(msg);
                if (!m.Success || !TrySplitSlash(m.Groups["a"].Value, out var a, out var ap) || !TrySplitSlash(m.Groups["b"].Value, out var b, out var bp))
                    return Fail(out ev);
                var bytes = Long(m.Groups["bytes"].Value);
                // Teardown does not say who initiated: the side with the lower (service) port is taken as the server.
                var aIsServer = ap is not null && bp is not null && ap < bp;
                ev = aIsServer
                    ? new Ev(b, a, bp, ap, Transport(m.Groups["p"].Value), FirewallAction.Allow, "traffic", Bytes: bytes)
                    : new Ev(a, b, ap, bp, Transport(m.Groups["p"].Value), FirewallAction.Allow, "traffic", Bytes: bytes);
                return ParseOutcome.Parsed;
            }
            case 313001:   // Denied ICMP type=8, code=0 from 203.0.113.5 on interface outside
            case 313008:   // Denied IPv6-ICMP type=128, code=0 from 2001:db8::5 on interface outside
            {
                var src = FromAddress(msg);
                if (!IsIp(src)) return Fail(out ev);
                ev = new Ev(src, null, null, null, id == 313008 ? "ipv6-icmp" : "icmp", FirewallAction.Deny, "traffic");
                return ParseOutcome.Parsed;
            }
            case 313004:   // Denied ICMP type=0, from laddr 203.0.113.5 on interface outside to 10.0.0.5: no matching session
            {
                var src = FromAddress(msg);
                var dst = Token(msg, " to ")?.TrimEnd(':');
                if (!IsIp(src)) return Fail(out ev);
                ev = new Ev(src, IsIp(dst) ? dst : null, null, null, "icmp", FirewallAction.Deny, "traffic");
                return ParseOutcome.Parsed;
            }
            case 313005:   // No matching connection for ICMP error message: icmp src outside:a dst inside:b (type 3, code 3) ...
                return SrcDst(msg, "icmp", FirewallAction.Drop, "traffic", null, out ev);
            case 710003:   // TCP access denied by ACL from a/p to outside:b/ssh
                return FromTo(msg, Word(msg, 0), FirewallAction.Deny, "traffic", out ev);
            case 733100:   // [ Scanning] drop rate-1 exceeded. ... (an address only for host objects)
            {
                var open = msg.IndexOf('[');
                var close = msg.IndexOf(']');
                if (open < 0 || close <= open) return ParseOutcome.Skipped;
                var obj = msg[(open + 1)..close].Trim();
                if (!IsIp(obj)) return ParseOutcome.Skipped;
                ev = new Ev(obj, null, null, null, null, FirewallAction.Alert, "threat", Threat: "Threat detection: drop rate exceeded");
                return ParseOutcome.Parsed;
            }
            case 733101:   // Host 203.0.113.5 is attacking. / Subnet 10.0.0.0 is targeted. Current burst rate ...
            {
                var ip = Token(msg, "Host ") ?? Token(msg, "Subnet ");
                if (!IsIp(ip)) return ParseOutcome.Skipped;
                var attacking = msg.Contains("is attacking", StringComparison.Ordinal);
                ev = attacking
                    ? new Ev(ip, null, null, null, null, FirewallAction.Alert, "threat", Threat: "Threat detection: host is attacking")
                    : new Ev(null, ip, null, null, null, FirewallAction.Alert, "threat", Threat: "Threat detection: host is targeted");
                return ParseOutcome.Parsed;
            }
            case 733102:   // Threat-detection adds host 203.0.113.5 to shun list
            {
                var ip = Token(msg, "adds host ");
                if (!IsIp(ip)) return ParseOutcome.Skipped;
                ev = new Ev(ip, null, null, null, null, FirewallAction.Deny, "threat", Threat: "Threat detection: host shunned");
                return ParseOutcome.Parsed;
            }
            case >= 400000 and <= 400050:
            {
                var m = Ips().Match(msg);
                if (!m.Success || !IsIp(m.Groups["s"].Value)) return Fail(out ev);
                var name = m.Groups["name"].Value.Trim();
                var proto = name.StartsWith("ICMP", StringComparison.OrdinalIgnoreCase) ? "icmp"
                    : name.StartsWith("TCP", StringComparison.OrdinalIgnoreCase) ? "tcp"
                    : name.StartsWith("UDP", StringComparison.OrdinalIgnoreCase) ? "udp" : null;
                ev = new Ev(m.Groups["s"].Value, IsIp(m.Groups["d"].Value) ? m.Groups["d"].Value : null, null, null, proto,
                    FirewallAction.Alert, "threat", "IPS:" + m.Groups["sig"].Value, name);
                return ParseOutcome.Parsed;
            }
            case 419002:   // Received duplicate TCP SYN from outside:a/p to inside:b/p with different initial sequence number.
                return FromTo(msg, "tcp", FirewallAction.Drop, "threat", out ev, "Duplicate TCP SYN");
            case 500004:   // Invalid transport field for protocol=TCP, from a/p to b/p
            {
                var proto = Token(msg, "protocol=")?.TrimEnd(',');
                return FromTo(msg, proto, FirewallAction.Drop, "threat", out ev, "Invalid transport field");
            }
            case 113005:   // AAA user authentication Rejected : reason = ... : server = x : user = admin : user IP = 203.0.113.9
            case 113015:   // AAA user authentication Rejected : reason = ... : local database : user = admin : user IP = 203.0.113.9
            case 113004:   // AAA user authentication Successful : server = x : user = admin [: user IP = ...]
            {
                var ip = Between(msg, "user IP = ", " ")?.TrimEnd(':', ',');
                if (!IsIp(ip)) return ParseOutcome.Skipped;
                var action = id == 113004 ? FirewallAction.Allow : FirewallAction.Deny;
                ev = new Ev(ip, null, null, null, null, action, "auth");
                return ParseOutcome.Parsed;
            }
            case 611102:   // User authentication failed: IP address: 203.0.113.9, Uname: admin
            {
                var ip = Token(msg, "IP address: ")?.TrimEnd(',');
                if (!IsIp(ip)) return ParseOutcome.Skipped;
                ev = new Ev(ip, null, null, null, null, FirewallAction.Deny, "auth");
                return ParseOutcome.Parsed;
            }
            case 605004:   // Login denied from 203.0.113.9/51234 to outside:198.51.100.1/ssh for user "admin"
            case 605005:   // Login permitted from 10.0.0.12/51234 to inside:10.0.0.1/ssh for user "admin"
                return FromTo(msg, "tcp", id == 605004 ? FirewallAction.Deny : FirewallAction.Allow, "auth", out ev);
            case 716039:   // Group <g> User <u> IP <ip> Authentication: rejected, Session Type: WebVPN.
            case 113039:   // Group <g> User <u> IP <ip> AnyConnect parent session started.
            case 716001:   // Group <g> User <u> IP <ip> WebVPN session started.
            case 722022:   // Group <g> User <u> IP <ip> TCP SVC connection established without compression
            case 722037:   // Group <g> User <u> IP <ip> SVC closing connection: DPD failure.
            case 722051:   // Group <g> User <u> IP <ip> IPv4 Address <10.10.0.5> IPv6 address <::> assigned to session
            {
                var m = GroupUserIp().Match(msg);
                if (!m.Success || !IsIp(m.Groups["ip"].Value)) return ParseOutcome.Skipped;
                var rejected = id == 716039 || m.Groups["rest"].Value.Contains("rejected", StringComparison.OrdinalIgnoreCase);
                var type = id is 716039 or 113039 or 716001 ? "auth" : "vpn";
                ev = new Ev(m.Groups["ip"].Value, null, null, null, null, rejected ? FirewallAction.Deny : FirewallAction.Allow, type, m.Groups["g"].Value);
                return ParseOutcome.Parsed;
            }
            case 430001:   // FTD intrusion event (Key: Value, ...)
            case 430002:   // FTD connection event at the beginning of a connection
            case 430003:   // FTD connection event at the end of a connection
                return FtdEvent(id, msg, out ev);
            default:
                return ParseOutcome.Skipped;
        }
    }

    private static ParseOutcome Fail(out Ev? ev)
    {
        ev = null;
        return ParseOutcome.Failed;
    }

    /// <summary>"... from a/p to iface:b/p ..." (ports optional, service names mapped).</summary>
    private static ParseOutcome FromTo(string msg, string? proto, FirewallAction action, string type, out Ev? ev, string? threat = null)
    {
        ev = null;
        // " to " is searched after " from " ("Deny IP due to Land Attack from a to b")
        var from = msg.IndexOf(" from ", StringComparison.Ordinal);
        if (from < 0)
            return ParseOutcome.Failed;
        var tail = msg[from..];
        if (!SplitAny(Token(tail, " from "), out var s, out var sp) || !SplitAny(Token(tail, " to "), out var d, out var dp))
            return ParseOutcome.Failed;
        var t = Transport(proto);
        var ports = t is "tcp" or "udp" or "sctp";
        ev = new Ev(s, d, ports ? sp : null, ports ? dp : null, t, action, type, Threat: threat);
        return ParseOutcome.Parsed;
    }

    /// <summary>"... src iface:a/p dst iface:b/p ..." (first occurrence).</summary>
    private static ParseOutcome SrcDst(string msg, string? proto, FirewallAction action, string type, string? rule, out Ev? ev)
    {
        ev = null;
        if (!SplitAny(Token(msg, " src "), out var s, out var sp) || !SplitAny(Token(msg, " dst "), out var d, out var dp))
            return ParseOutcome.Failed;
        var t = Transport(proto);
        var ports = t is "tcp" or "udp" or "sctp";
        ev = new Ev(s, d, ports ? sp : null, ports ? dp : null, t, action, type, rule);
        return ParseOutcome.Parsed;
    }

    /// <summary>"outside:203.0.113.5/51234", "203.0.113.5/ssh", "outside:203.0.113.5" -> address + port.</summary>
    private static bool SplitAny(string? token, out string ip, out int? port)
    {
        ip = string.Empty;
        port = null;
        if (string.IsNullOrEmpty(token))
            return false;
        var t = token.TrimEnd(',', '.', ':');
        var slash = t.LastIndexOf('/');
        if (slash > 0 && !int.TryParse(t.AsSpan(slash + 1), out _))
        {
            var service = t[(slash + 1)..];
            t = t[..slash];
            if (Services.TryGetValue(service, out var known))
                port = known;
        }
        if (!TrySplitSlash(t, out ip, out var p))
            return false;
        port ??= p;
        return true;
    }

    private static string? FromAddress(string msg)
    {
        var t = Token(msg, " from ");
        if (t is "laddr" or "addr")
        {
            var i = msg.IndexOf(" from ", StringComparison.Ordinal);
            t = Token(msg[(i + 6)..], " ");
        }
        return t?.TrimEnd(',', ':');
    }

    /// <summary>The non-space token right after <paramref name="marker"/> (first occurrence).</summary>
    private static string? Token(string s, string marker)
    {
        var i = s.IndexOf(marker, StringComparison.Ordinal);
        if (i < 0)
            return null;
        var start = i + marker.Length;
        while (start < s.Length && s[start] == ' ')
            start++;
        var end = s.IndexOf(' ', start);
        var token = end < 0 ? s[start..] : s[start..end];
        return token.Length == 0 ? null : token;
    }

    private static string? Between(string s, string start, string end)
    {
        var i = s.IndexOf(start, StringComparison.Ordinal);
        if (i < 0)
            return null;
        i += start.Length;
        var j = s.IndexOf(end, i, StringComparison.Ordinal);
        return (j < 0 ? s[i..] : s[i..j]).Trim();
    }

    private static string? Quoted(string s, string after)
    {
        var i = s.IndexOf(after + "\"", StringComparison.Ordinal);
        if (i < 0)
            return null;
        i += after.Length + 1;
        var j = s.IndexOf('"', i);
        return j < 0 ? null : s[i..j];
    }

    /// <summary>n-th space-separated word (0-based) or null.</summary>
    private static string? Word(string s, int n)
    {
        var start = 0;
        for (var k = 0; k <= n; k++)
        {
            while (start < s.Length && s[start] == ' ')
                start++;
            if (start >= s.Length)
                return null;
            var end = s.IndexOf(' ', start);
            if (end < 0)
                end = s.Length;
            if (k == n)
                return s[start..end];
            start = end;
        }
        return null;
    }

    // FTD "Key: Value, Key: Value" events
    private static ParseOutcome FtdEvent(int id, string msg, out Ev? ev)
    {
        ev = null;
        var src = FtdValue(msg, "SrcIP");
        var dst = FtdValue(msg, "DstIP");
        if (!IsIp(src))
            return ParseOutcome.Skipped;
        var proto = Transport(FtdValue(msg, "Protocol"));
        var sp = Port(FtdValue(msg, "SrcPort"));
        var dp = Port(FtdValue(msg, "DstPort"));
        var rule = FtdValue(msg, "AccessControlRuleName");
        if (id == 430001)
        {
            var inline = FtdValue(msg, "InlineResult")?.ToLowerInvariant();
            var action = inline is "blocked" or "dropped" ? FirewallAction.Drop : FirewallAction.Alert;
            ev = new Ev(src, IsIp(dst) ? dst : null, sp, dp, proto, action, "threat", FtdValue(msg, "IntrusionPolicy") ?? rule,
                FtdValue(msg, "Message") ?? FtdValue(msg, "Classification"));
            return ParseOutcome.Parsed;
        }
        var word = FtdValue(msg, "AccessControlRuleAction");
        var act = word?.ToLowerInvariant() switch
        {
            "allow" or "trust" => FirewallAction.Allow,
            "block" => FirewallAction.Deny,
            "block with reset" => FirewallAction.Reject,
            _ => Action(word)
        };
        long? bytes = Long(FtdValue(msg, "InitiatorBytes")) is { } ib ? ib + (Long(FtdValue(msg, "ResponderBytes")) ?? 0) : null;
        ev = new Ev(src, IsIp(dst) ? dst : null, sp, dp, proto, act, "traffic", rule, Bytes: bytes);
        return ParseOutcome.Parsed;
    }

    private static string? FtdValue(string msg, string key)
    {
        var marker = key + ": ";
        var i = msg.StartsWith(marker, StringComparison.Ordinal) ? 0 : msg.IndexOf(", " + marker, StringComparison.Ordinal);
        if (i < 0)
            return null;
        var start = i == 0 && msg.StartsWith(marker, StringComparison.Ordinal) ? marker.Length : i + 2 + marker.Length;
        // the value ends at ", NextKey: "
        var end = start;
        while (true)
        {
            var comma = msg.IndexOf(", ", end, StringComparison.Ordinal);
            if (comma < 0) { end = msg.Length; break; }
            var k = comma + 2;
            var j = k;
            // keys are words, some with a space ("Prefilter Policy")
            while (j < msg.Length && j - k < 40 && (char.IsLetterOrDigit(msg[j]) || msg[j] == ' ' && j + 1 < msg.Length && char.IsUpper(msg[j + 1])))
                j++;
            if (j > k && j + 1 < msg.Length && msg[j] == ':' && msg[j + 1] == ' ' && char.IsUpper(msg[k]))
            {
                end = comma;
                break;
            }
            end = comma + 2;
        }
        var v = msg[start..end].Trim();
        return v.Length == 0 ? null : v;
    }
}
