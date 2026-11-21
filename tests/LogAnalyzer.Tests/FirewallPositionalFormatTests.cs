using System.Diagnostics;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.Services.LogFormats;

namespace LogAnalyzer.Tests;

/// <summary>Shared helpers for the positional firewall format tests.</summary>
internal static class Fw
{
    /// <summary>Reference time for year-less syslog stamps; local times are UTC.</summary>
    public static readonly LogParseContext Utc = new(new DateTimeOffset(2026, 11, 21, 12, 0, 0, TimeSpan.Zero), TimeSpan.Zero);

    /// <summary>Same, but the firewall logs local time in UTC+1.</summary>
    public static readonly LogParseContext Plus1 = new(new DateTimeOffset(2026, 11, 21, 12, 0, 0, TimeSpan.Zero), TimeSpan.FromHours(1));

    public static DateTimeOffset T(int h, int m, int s, double offsetHours = 0) =>
        new(2026, 11, 21, h, m, s, TimeSpan.FromHours(offsetHours));

    /// <summary>Same instant AND same offset (DateTimeOffset equality alone ignores the offset).</summary>
    public static void Time(DateTimeOffset expected, DateTimeOffset actual)
    {
        Assert.Equal(expected, actual);
        Assert.Equal(expected.Offset, actual.Offset);
    }

    /// <summary>Largest number of time stamps inside any window of the given length.</summary>
    public static int MaxInWindow(IEnumerable<DateTimeOffset> times, TimeSpan window)
    {
        var t = times.OrderBy(x => x).ToList();
        int best = 0, start = 0;
        for (var end = 0; end < t.Count; end++)
        {
            while (t[end] - t[start] > window)
                start++;
            best = Math.Max(best, end - start + 1);
        }
        return best;
    }

    public static ParsedLine Parsed(ILogFormat format, string line, LogParseContext? context = null)
    {
        var outcome = format.CreateParser(context ?? Utc).Parse(line, out var result);
        Assert.True(outcome == ParseOutcome.Parsed, $"{format.Id}: expected Parsed but got {outcome} for: {line}");
        Assert.NotNull(result);
        return result!;
    }

    public static void Outcome(ILogFormat format, string line, ParseOutcome expected, LogParseContext? context = null)
    {
        var outcome = format.CreateParser(context ?? Utc).Parse(line, out var result);
        Assert.True(outcome == expected, $"{format.Id}: expected {expected} but got {outcome} for: {line}");
        if (expected != ParseOutcome.Parsed)
            Assert.Null(result);
    }

    public static void Network(ParsedLine p, string src, string? dst, int? sport, int? dport, string? transport, FirewallAction action,
        string eventType, string? rule = null, string? threat = null, string? device = null, long? bytes = null)
    {
        Assert.Equal(src, p.ClientIp);
        Assert.Equal(dst, p.DestinationIp);
        Assert.Equal(sport, p.SourcePort);
        Assert.Equal(dport, p.DestinationPort);
        Assert.Equal(transport, p.Transport);
        Assert.Equal(action, p.Action);
        Assert.Equal(action == FirewallAction.Unknown ? "EVENT" : action.ToString().ToUpperInvariant(), p.Method);
        Assert.Equal(eventType, p.EventType);
        Assert.Equal(rule, p.RuleName);
        Assert.Equal(threat, p.ThreatName);
        Assert.Equal(device, p.Device);
        Assert.Equal(bytes, p.ResponseSize);
        Assert.Equal(0, p.StatusCode);
        Assert.False(string.IsNullOrWhiteSpace(p.Url));
        Assert.Null(p.UserAgent);
        Assert.Null(p.Referrer);
    }

    public static string SamplesDir
    {
        get
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "samples", "sample-access.log")))
                dir = dir.Parent;
            Assert.NotNull(dir);
            return Path.Combine(dir!.FullName, "samples");
        }
    }

    public static string[] Sample(string name) => File.ReadAllLines(Path.Combine(SamplesDir, "firewall", name));

    public static string[] AccessLog() => File.ReadAllLines(Path.Combine(SamplesDir, "sample-access.log"));

    /// <summary>format id -> its sample file.</summary>
    public static readonly (string Id, string File)[] SampleFiles =
    [
        ("paloalto", "paloalto.log"), ("cisco-asa", "cisco-asa.log"), ("pfsense", "pfsense.log"), ("netfilter", "iptables-ufw.log"),
        ("windows-firewall", "windows-firewall.log"), ("juniper-srx", "juniper-srx.log"), ("watchguard", "watchguard.log"),
        ("mikrotik", "mikrotik.log"), ("aws-vpc-flow", "aws-vpc-flow.log")
    ];

    public static ILogFormat Format(string id) => LogFormatRegistry.Find(id) ?? throw new InvalidOperationException(id);
}

public class PaloAltoFormatTests
{
    private readonly ILogFormat _f = new PaloAltoFormat();

    [Fact]
    public void Traffic_deny_without_syslog_header_uses_generated_time_and_serial()
    {
        var p = Fw.Parsed(_f, "1,2026/11/21 10:00:00,012801000000,TRAFFIC,end,2561,2026/11/21 10:00:01,203.0.113.5,10.0.0.5,0.0.0.0,0.0.0.0,deny-all,,,ssh,vsys1,untrust,trust,ethernet1/1,ethernet1/2,Forward,2026/11/21 10:00:00,12345,1,51234,22,0,0,0x0,tcp,deny,74,74,0,1", Fw.Plus1);
        Fw.Time(Fw.T(10, 0, 1, 1), p.Timestamp);
        Fw.Network(p, "203.0.113.5", "10.0.0.5", 51234, 22, "tcp", FirewallAction.Deny, "traffic", "deny-all", null, "012801000000", 74);
        Assert.Contains("ssh", p.Url);
    }

    [Fact]
    public void Traffic_allow_in_syslog_envelope_uses_host_name()
    {
        var p = Fw.Parsed(_f, Fw.Sample("paloalto.log")[0]);
        Fw.Time(Fw.T(10, 0, 0), p.Timestamp);
        Fw.Network(p, "198.51.100.10", "10.0.0.20", 50000, 443, "tcp", FirewallAction.Allow, "traffic", "allow-web", null, "PA-3220", 5120);
    }

    [Fact]
    public void Rfc5424_envelope_is_accepted()
    {
        var p = Fw.Parsed(_f, "<14>1 2026-11-21T10:00:00+01:00 PA-3220 - - - - 1,2026/11/21 10:00:00,012801000000,TRAFFIC,drop,2561,2026/11/21 10:00:00,203.0.113.5,10.0.0.5,0.0.0.0,0.0.0.0,deny-all,,,not-applicable,vsys1,untrust,trust,ethernet1/1,,Forward,2026/11/21 10:00:00,0,1,51234,23,0,0,0x0,tcp,drop,60,60,0,1");
        Fw.Network(p, "203.0.113.5", "10.0.0.5", 51234, 23, "tcp", FirewallAction.Drop, "traffic", "deny-all", null, "PA-3220", 60);
    }

    [Fact]
    public void Threat_with_quoted_comma_field_is_a_threat_event()
    {
        var line = Fw.Sample("paloalto.log").Single(l => l.Contains("Generic SQL Injection"));
        var p = Fw.Parsed(_f, line);
        Fw.Time(Fw.T(10, 12, 0), p.Timestamp);
        Fw.Network(p, "192.0.2.44", "10.0.0.20", 43001, 80, "tcp", FirewallAction.Reject, "threat", "allow-web",
            "Generic SQL Injection Attempt(31477)", "PA-3220");
        Assert.Contains("UNION SELECT", p.Url);
        Assert.Contains("critical", p.Url);
    }

    [Theory]
    [InlineData("alert", FirewallAction.Alert)]
    [InlineData("drop", FirewallAction.Drop)]
    [InlineData("reset-client", FirewallAction.Reject)]
    [InlineData("block-ip", FirewallAction.Deny)]
    [InlineData("sinkhole", FirewallAction.Deny)]
    [InlineData("allow", FirewallAction.Alert)]
    public void Threat_actions_are_normalised(string action, FirewallAction expected)
    {
        var line = $"1,2026/11/21 10:00:00,012801000000,THREAT,vulnerability,2561,2026/11/21 10:00:00,203.0.113.5,10.0.0.5,0.0.0.0,0.0.0.0,allow-web,,,web-browsing,vsys1,untrust,trust,ethernet1/1,ethernet1/2,Forward,2026/11/21 10:00:00,1,1,51234,80,0,0,0x0,tcp,{action},\"x\",Test(1),any,high,client-to-server";
        Assert.Equal(expected, Fw.Parsed(_f, line).Action);
    }

    [Fact]
    public void Url_filtering_alert_is_allowed_web_traffic_not_a_threat()
    {
        var p = Fw.Parsed(_f, Fw.Sample("paloalto.log").Single(l => l.Contains(",url,")));
        Assert.Equal(FirewallAction.Allow, p.Action);
        Assert.Equal("url", p.EventType);
        Assert.Null(p.ThreatName);
    }

    [Fact]
    public void System_auth_fail_and_globalprotect_failure_are_auth_denies()
    {
        var sample = Fw.Sample("paloalto.log");
        var sys = Fw.Parsed(_f, sample.First(l => l.Contains("auth-fail")));
        Fw.Network(sys, "203.0.113.9", null, null, null, null, FirewallAction.Deny, "auth", null, null, "PA-3220");
        Assert.Contains("admin", sys.Url);

        var gp = Fw.Parsed(_f, sample.Single(l => l.Contains("GLOBALPROTECT") && l.Contains("failure")));
        Fw.Network(gp, "198.51.100.99", null, null, null, null, FirewallAction.Deny, "auth", "GP-Portal", null, "PA-3220");
        Assert.Contains("jdoe", gp.Url);

        var ok = Fw.Parsed(_f, sample.Single(l => l.Contains("GLOBALPROTECT") && l.Contains("success")));
        Assert.Equal(FirewallAction.Allow, ok.Action);
    }

    [Fact]
    public void Config_and_other_log_types_are_skipped()
    {
        Fw.Outcome(_f, Fw.Sample("paloalto.log").Single(l => l.Contains(",CONFIG,")), ParseOutcome.Skipped);
        Fw.Outcome(_f, "1,2026/11/21 10:00:00,012801000000,SYSTEM,general,0,2026/11/21 10:00:00,,general,,0,0,general,informational,\"Commit job succeeded\",1,0x0", ParseOutcome.Skipped);
    }

    [Fact]
    public void Garbage_and_broken_lines_fail()
    {
        Fw.Outcome(_f, "hello,TRAFFIC,world", ParseOutcome.Failed);
        Fw.Outcome(_f, "1,not a date,012801000000,TRAFFIC,end,2561,x,203.0.113.5,10.0.0.5,0.0.0.0,0.0.0.0,r,,,ssh,vsys1,a,b,c,d,e,f,1,1,1,22,0,0,0x0,tcp,deny,1", ParseOutcome.Failed);
        Fw.Outcome(_f, "1,2026/11/21 10:00:00,012801000000,TRAFFIC,end,2561,2026/11/21 10:00:00,\"unterminated", ParseOutcome.Failed);
    }
}

public class CiscoAsaFormatTests
{
    private readonly ILogFormat _f = new CiscoAsaFormat();
    private const string Prefix = "Nov 21 2026 10:00:00 fw01 : ";

    [Fact]
    public void Deny_106023_with_cisco_timestamp_and_host()
    {
        var p = Fw.Parsed(_f, Prefix + "%ASA-4-106023: Deny tcp src outside:203.0.113.5/51234 dst inside:10.0.0.5/22 by access-group \"OUTSIDE_IN\" [0x0, 0x0]", Fw.Plus1);
        Fw.Time(Fw.T(10, 0, 0, 1), p.Timestamp);
        Fw.Network(p, "203.0.113.5", "10.0.0.5", 51234, 22, "tcp", FirewallAction.Deny, "traffic", "OUTSIDE_IN", null, "fw01");
        Assert.Equal("Deny tcp src outside:203.0.113.5/51234 dst inside:10.0.0.5/22 by access-group \"OUTSIDE_IN\"", p.Url);
    }

    [Theory]
    // syslog header (BSD) with host
    [InlineData("<164>Nov 21 10:00:00 fw01 %ASA-4-106023: Deny udp src outside:203.0.113.5/5000 dst inside:10.0.0.5/53 by access-group \"OUTSIDE_IN\" [0x0, 0x0]", "fw01", 0)]
    // ASA "logging timestamp" without host
    [InlineData("Nov 21 2026 10:00:00: %ASA-4-106023: Deny udp src outside:203.0.113.5/5000 dst inside:10.0.0.5/53 by access-group \"OUTSIDE_IN\" [0x0, 0x0]", null, 1)]
    // FTD "<166>:Nov 21 10:00:00 UTC:" - UTC wins over the file's default offset
    [InlineData("<166>:Nov 21 10:00:00 UTC: %FTD-4-106023: Deny udp src outside:203.0.113.5/5000 dst inside:10.0.0.5/53 by access-group \"OUTSIDE_IN\" [0x0, 0x0]", null, 0)]
    [InlineData("<166>Nov 21 2026 10:00:00 UTC: %ASA-session-4-106023: Deny udp src outside:203.0.113.5/5000 dst inside:10.0.0.5/53 by access-group \"OUTSIDE_IN\" [0x0, 0x0]", null, 0)]
    [InlineData("<164>1 2026-11-21T10:00:00Z fw01 - - - %PIX-4-106023: Deny udp src outside:203.0.113.5/5000 dst inside:10.0.0.5/53 by access-group \"OUTSIDE_IN\" [0x0, 0x0]", "fw01", 0)]
    public void Time_stamp_variants(string line, string? host, double offset)
    {
        var p = Fw.Parsed(_f, line, Fw.Plus1);
        // BSD stamps without zone are local (+1), the others carry UTC
        var expectedOffset = line.StartsWith("<164>Nov") ? 1 : offset;
        Fw.Time(Fw.T(10, 0, 0, expectedOffset), p.Timestamp);
        Assert.Equal(host, p.Device);
        Assert.Equal("udp", p.Transport);
        Assert.Equal(53, p.DestinationPort);
    }

    [Fact]
    public void Line_without_any_time_stamp_fails()
    {
        Fw.Outcome(_f, "%ASA-4-106023: Deny tcp src outside:203.0.113.5/51234 dst inside:10.0.0.5/22 by access-group \"OUTSIDE_IN\" [0x0, 0x0]", ParseOutcome.Failed);
    }

    public static TheoryData<string, string, string?, int?, int?, string?, FirewallAction, string, string?, string?> Messages => new()
    {
        { "%ASA-2-106001: Inbound TCP connection denied from 203.0.113.5/51234 to 10.0.0.5/22 flags SYN on interface outside", "203.0.113.5", "10.0.0.5", 51234, 22, "tcp", FirewallAction.Deny, "traffic", null, null },
        { "%ASA-2-106002: tcp Connection denied by outbound list OUT_ACL src 10.0.0.23 dest 198.51.100.66", "10.0.0.23", "198.51.100.66", null, null, "tcp", FirewallAction.Deny, "traffic", "OUT_ACL", null },
        { "%ASA-2-106006: Deny inbound UDP from 203.0.113.5/5000 to 10.0.0.5/161 on interface outside", "203.0.113.5", "10.0.0.5", 5000, 161, "udp", FirewallAction.Deny, "traffic", null, null },
        { "%ASA-2-106007: Deny inbound UDP from 203.0.113.5/5000 to 10.0.0.5/53 due to DNS Query", "203.0.113.5", "10.0.0.5", 5000, 53, "udp", FirewallAction.Deny, "traffic", null, null },
        { "%ASA-3-106010: Deny inbound tcp src outside:203.0.113.5/51234 dst inside:10.0.0.5/445", "203.0.113.5", "10.0.0.5", 51234, 445, "tcp", FirewallAction.Deny, "traffic", null, null },
        { "%ASA-3-106014: Deny inbound icmp src outside:203.0.113.5 dst inside:10.0.0.5 (type 8, code 0)", "203.0.113.5", "10.0.0.5", null, null, "icmp", FirewallAction.Deny, "traffic", null, null },
        { "%ASA-6-106015: Deny TCP (no connection) from 203.0.113.5/51234 to 10.0.0.5/443 flags RST  on interface outside", "203.0.113.5", "10.0.0.5", 51234, 443, "tcp", FirewallAction.Deny, "traffic", null, null },
        { "%ASA-2-106017: Deny IP due to Land Attack from 203.0.113.5 to 203.0.113.5", "203.0.113.5", "203.0.113.5", null, null, "ip", FirewallAction.Deny, "threat", null, "Land attack" },
        { "%ASA-1-106021: Deny TCP reverse path check from 10.0.0.5 to 10.0.0.6 on interface outside", "10.0.0.5", "10.0.0.6", null, null, "tcp", FirewallAction.Deny, "threat", null, "Reverse path check failed (spoofed source)" },
        { "%ASA-4-106023: Deny icmp src outside:203.0.113.5 dst inside:10.0.0.5 (type 8, code 0) by access-group \"OUTSIDE_IN\" [0x0, 0x0]", "203.0.113.5", "10.0.0.5", null, null, "icmp", FirewallAction.Deny, "traffic", "OUTSIDE_IN", null },
        { "%ASA-6-106100: access-list OUTSIDE_IN denied tcp outside/203.0.113.5(51234) -> inside/10.0.0.5(3389) hit-cnt 1 first hit [0x91c26a3, 0x0]", "203.0.113.5", "10.0.0.5", 51234, 3389, "tcp", FirewallAction.Deny, "traffic", "OUTSIDE_IN", null },
        { "%ASA-6-106100: access-list INSIDE_OUT permitted udp inside/10.0.0.12(53000) -> outside/198.51.100.53(53) hit-cnt 3 300-second interval [0x1, 0x0]", "10.0.0.12", "198.51.100.53", 53000, 53, "udp", FirewallAction.Allow, "traffic", "INSIDE_OUT", null },
        { "%ASA-6-302013: Built inbound TCP connection 5000 for outside:198.51.100.10/50000 (198.51.100.10/50000) to inside:10.0.0.20/443 (198.51.100.1/443)", "198.51.100.10", "10.0.0.20", 50000, 443, "tcp", FirewallAction.Allow, "traffic", null, null },
        { "%ASA-6-302013: Built outbound TCP connection 7001 for outside:198.51.100.66/4444 (198.51.100.66/4444) to inside:10.0.0.23/50999 (198.51.100.1/50999)", "10.0.0.23", "198.51.100.66", 50999, 4444, "tcp", FirewallAction.Allow, "traffic", null, null },
        { "%ASA-6-302015: Built outbound UDP connection 9 for outside:198.51.100.53/53 (198.51.100.53/53) to inside:10.0.0.12/53000 (198.51.100.1/53000)", "10.0.0.12", "198.51.100.53", 53000, 53, "udp", FirewallAction.Allow, "traffic", null, null },
        { "%ASA-6-313001: Denied ICMP type=8, code=0 from 203.0.113.5 on interface outside", "203.0.113.5", null, null, null, "icmp", FirewallAction.Deny, "traffic", null, null },
        { "%ASA-4-313004: Denied ICMP type=0, from laddr 203.0.113.5 on interface outside to 10.0.0.5: no matching session", "203.0.113.5", "10.0.0.5", null, null, "icmp", FirewallAction.Deny, "traffic", null, null },
        { "%ASA-4-313005: No matching connection for ICMP error message: icmp src outside:203.0.113.5 dst inside:10.0.0.5 (type 3, code 3) on outside interface. Original IP payload: udp src 10.0.0.5/53 dst 203.0.113.5/5000.", "203.0.113.5", "10.0.0.5", null, null, "icmp", FirewallAction.Drop, "traffic", null, null },
        { "%ASA-3-313008: Denied IPv6-ICMP type=128, code=0 from 2001:db8::5 on interface outside", "2001:db8::5", null, null, null, "ipv6-icmp", FirewallAction.Deny, "traffic", null, null },
        { "%ASA-3-710003: TCP access denied by ACL from 203.0.113.5/51234 to outside:198.51.100.1/ssh", "203.0.113.5", "198.51.100.1", 51234, 22, "tcp", FirewallAction.Deny, "traffic", null, null },
        { "%ASA-4-733100: [ 203.0.113.5] drop rate-1 exceeded. Current burst rate is 10 per second, max configured rate is 10", "203.0.113.5", null, null, null, null, FirewallAction.Alert, "threat", null, "Threat detection: drop rate exceeded" },
        { "%ASA-4-733101: Host 203.0.113.5 is attacking. Current burst rate is 12 per second, max configured rate is 10", "203.0.113.5", null, null, null, null, FirewallAction.Alert, "threat", null, "Threat detection: host is attacking" },
        { "%ASA-4-733101: Host 10.0.0.5 is targeted. Current burst rate is 12 per second, max configured rate is 10", "-", "10.0.0.5", null, null, null, FirewallAction.Alert, "threat", null, "Threat detection: host is targeted" },
        { "%ASA-4-733102: Threat-detection adds host 203.0.113.5 to shun list", "203.0.113.5", null, null, null, null, FirewallAction.Deny, "threat", null, "Threat detection: host shunned" },
        { "%ASA-4-400010: IPS:2000 ICMP Echo Reply from 203.0.113.5 to 10.0.0.5 on interface outside", "203.0.113.5", "10.0.0.5", null, null, "icmp", FirewallAction.Alert, "threat", "IPS:2000", "ICMP Echo Reply" },
        { "%ASA-4-400032: IPS:3040 TCP NULL flags from 203.0.113.5 to 10.0.0.5 on interface outside", "203.0.113.5", "10.0.0.5", null, null, "tcp", FirewallAction.Alert, "threat", "IPS:3040", "TCP NULL flags" },
        { "%ASA-4-419002: Received duplicate TCP SYN from outside:203.0.113.5/51234 to inside:10.0.0.5/443 with different initial sequence number.", "203.0.113.5", "10.0.0.5", 51234, 443, "tcp", FirewallAction.Drop, "threat", null, "Duplicate TCP SYN" },
        { "%ASA-4-500004: Invalid transport field for protocol=UDP, from 203.0.113.5/0 to 10.0.0.5/0", "203.0.113.5", "10.0.0.5", 0, 0, "udp", FirewallAction.Drop, "threat", null, "Invalid transport field" },
        { "%ASA-6-113015: AAA user authentication Rejected : reason = Invalid password : local database : user = admin : user IP = 203.0.113.9", "203.0.113.9", null, null, null, null, FirewallAction.Deny, "auth", null, null },
        { "%ASA-6-113005: AAA user authentication Rejected : reason = AAA failure : server = 10.0.0.2 : user = ***** : user IP = 203.0.113.9", "203.0.113.9", null, null, null, null, FirewallAction.Deny, "auth", null, null },
        { "%ASA-6-611102: User authentication failed: IP address: 203.0.113.9, Uname: admin", "203.0.113.9", null, null, null, null, FirewallAction.Deny, "auth", null, null },
        { "%ASA-6-605004: Login denied from 203.0.113.9/51234 to outside:198.51.100.1/ssh for user \"admin\"", "203.0.113.9", "198.51.100.1", 51234, 22, "tcp", FirewallAction.Deny, "auth", null, null },
        { "%ASA-6-605005: Login permitted from 10.0.0.12/51234 to inside:10.0.0.1/https for user \"admin\"", "10.0.0.12", "10.0.0.1", 51234, 443, "tcp", FirewallAction.Allow, "auth", null, null },
        { "%ASA-6-716039: Group <DfltGrpPolicy> User <jdoe> IP <198.51.100.99> Authentication: rejected, Session Type: WebVPN.", "198.51.100.99", null, null, null, null, FirewallAction.Deny, "auth", "DfltGrpPolicy", null },
        { "%ASA-4-113039: Group <GroupPolicy_VPN> User <jdoe> IP <198.51.100.99> AnyConnect parent session started.", "198.51.100.99", null, null, null, null, FirewallAction.Allow, "auth", "GroupPolicy_VPN", null },
        { "%ASA-4-722037: Group <GroupPolicy_VPN> User <jdoe> IP <198.51.100.99> SVC closing connection: DPD failure.", "198.51.100.99", null, null, null, null, FirewallAction.Allow, "vpn", "GroupPolicy_VPN", null },
        { "%FTD-1-430002: EventPriority: Low, DeviceUUID: 00000000-0000-0000-0000-000000000001, InstanceID: 1, FirstPacketSecond: 2026-11-21T10:00:00Z, ConnectionID: 1, AccessControlRuleAction: Block, SrcIP: 203.0.113.5, DstIP: 10.0.0.5, SrcPort: 51234, DstPort: 22, Protocol: tcp, IngressInterface: outside, EgressInterface: inside, ACPolicy: Default, AccessControlRuleName: Block-SSH, Prefilter Policy: Default", "203.0.113.5", "10.0.0.5", 51234, 22, "tcp", FirewallAction.Deny, "traffic", "Block-SSH", null },
        { "%FTD-1-430001: EventPriority: High, DeviceUUID: 00000000-0000-0000-0000-000000000001, InstanceID: 1, SrcIP: 192.0.2.44, DstIP: 10.0.0.20, SrcPort: 43001, DstPort: 80, Protocol: tcp, Priority: 1, GID: 1, SID: 1000001, Revision: 1, Message: SERVER-WEBAPP SQL injection attempt, Classification: Web Application Attack, IntrusionPolicy: Balanced, InlineResult: blocked", "192.0.2.44", "10.0.0.20", 43001, 80, "tcp", FirewallAction.Drop, "threat", "Balanced", "SERVER-WEBAPP SQL injection attempt" }
    };

    [Theory]
    [MemberData(nameof(Messages))]
    public void Message_id_families(string message, string src, string? dst, int? sport, int? dport, string? transport,
        FirewallAction action, string eventType, string? rule, string? threat)
    {
        var p = Fw.Parsed(_f, Prefix + message);
        Fw.Time(Fw.T(10, 0, 0), p.Timestamp);
        Fw.Network(p, src, dst, sport, dport, transport, action, eventType, rule, threat, "fw01");
        Assert.DoesNotContain("%ASA", p.Url);
    }

    [Fact]
    public void Teardown_takes_the_service_port_side_as_destination_and_keeps_bytes()
    {
        var inbound = Fw.Parsed(_f, Prefix + "%ASA-6-302014: Teardown TCP connection 5000 for outside:198.51.100.10/50000 to inside:10.0.0.20/443 duration 0:00:04 bytes 4096 TCP FINs");
        Fw.Network(inbound, "198.51.100.10", "10.0.0.20", 50000, 443, "tcp", FirewallAction.Allow, "traffic", null, null, "fw01", 4096);
        var outbound = Fw.Parsed(_f, Prefix + "%ASA-6-302016: Teardown UDP connection 9 for outside:198.51.100.53/53 to inside:10.0.0.12/53000 duration 0:02:01 bytes 312");
        Fw.Network(outbound, "10.0.0.12", "198.51.100.53", 53000, 53, "udp", FirewallAction.Allow, "traffic", null, null, "fw01", 312);
    }

    [Fact]
    public void Other_cisco_messages_and_ids_without_addresses_are_skipped()
    {
        Fw.Outcome(_f, Prefix + "%ASA-5-111008: User 'admin' executed the 'write memory' command.", ParseOutcome.Skipped);
        Fw.Outcome(_f, Prefix + "%ASA-4-733100: [ Scanning] drop rate-1 exceeded. Current burst rate is 10 per second", ParseOutcome.Skipped);
        Fw.Outcome(_f, Prefix + "%ASA-6-113004: AAA user authentication Successful : server = 10.0.0.2 : user = admin", ParseOutcome.Skipped);
        Fw.Outcome(_f, "%ASA-6-199018: no time stamp needed for skipped lines", ParseOutcome.Skipped);
    }

    [Fact]
    public void Broken_and_foreign_lines_fail()
    {
        Fw.Outcome(_f, Prefix + "%ASA-4-106023: Deny tcp garbage", ParseOutcome.Failed);
        Fw.Outcome(_f, Prefix + "%ASA-x-106023: Deny", ParseOutcome.Failed);
        Fw.Outcome(_f, "Nov 21 10:00:00 web01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.5 PROTO=TCP SPT=1 DPT=22", ParseOutcome.Failed);
        Fw.Outcome(_f, "100% sure %not cisco", ParseOutcome.Failed);
    }
}

public class PfSenseFormatTests
{
    private readonly ILogFormat _f = new PfSenseFormat();

    [Fact]
    public void Rfc5424_block_is_a_deny_with_tracker_as_rule()
    {
        var p = Fw.Parsed(_f, "<134>1 2026-11-21T10:00:00+00:00 fw01.home.arpa filterlog 12345 - [meta sequenceId=\"1\"] 5,,,1000000103,em0,match,block,in,4,0x0,,64,12345,0,none,6,tcp,60,203.0.113.5,10.0.0.5,51234,22,0,S,123456789,,64240,,mss;sackOK;TS;nop;wscale", Fw.Plus1);
        Fw.Time(Fw.T(10, 0, 0), p.Timestamp);
        Fw.Network(p, "203.0.113.5", "10.0.0.5", 51234, 22, "tcp", FirewallAction.Deny, "traffic", "1000000103", null, "fw01.home.arpa", 60);
        Assert.Contains("em0", p.Url);
    }

    [Fact]
    public void Bsd_pass_is_an_allow_with_local_time()
    {
        var p = Fw.Parsed(_f, "Nov 21 10:00:00 fw01 filterlog[12345]: 7,,,1000000207,em0,match,pass,in,4,0x0,,64,1,0,DF,17,udp,48,198.51.100.53,10.0.0.12,53,53000,40", Fw.Plus1);
        Fw.Time(Fw.T(10, 0, 0, 1), p.Timestamp);
        Fw.Network(p, "198.51.100.53", "10.0.0.12", 53, 53000, "udp", FirewallAction.Allow, "traffic", "1000000207", null, "fw01", 48);
    }

    [Fact]
    public void Ipv6_and_icmp_and_reject_and_rule_number_fallback()
    {
        var v6 = Fw.Parsed(_f, "Nov 21 10:00:00 fw01 filterlog[1]: 5,,,1000000103,em0,match,block,in,6,0x00,0x00000,64,udp,17,40,2001:db8::5,2001:db8:1::20,41700,161,40");
        Fw.Network(v6, "2001:db8::5", "2001:db8:1::20", 41700, 161, "udp", FirewallAction.Deny, "traffic", "1000000103", null, "fw01", 40);

        var icmp = Fw.Parsed(_f, "Nov 21 10:00:00 fw01 filterlog[1]: 5,,,,em0,match,reject,in,4,0x0,,64,1,0,none,1,icmp,84,203.0.113.5,10.0.0.5,request,1234,1");
        Fw.Network(icmp, "203.0.113.5", "10.0.0.5", null, null, "icmp", FirewallAction.Reject, "traffic", "5", null, "fw01", 84);
    }

    [Fact]
    public void Opnsense_without_host_is_parsed()
    {
        var p = Fw.Parsed(_f, "Nov 21 10:00:00 filterlog[1]: 5,,,02f4bab031b57d1e30553ce08e0ec131,igb0,match,block,in,4,0x0,,64,1,0,DF,6,tcp,60,203.0.113.5,10.0.0.5,51234,3389,0,S,1,,64240,,mss");
        Fw.Network(p, "203.0.113.5", "10.0.0.5", 51234, 3389, "tcp", FirewallAction.Deny, "traffic", "02f4bab031b57d1e30553ce08e0ec131", null, null, 60);
    }

    [Fact]
    public void Non_decision_actions_are_skipped_and_foreign_lines_fail()
    {
        Fw.Outcome(_f, "Nov 21 10:00:00 fw01 filterlog[1]: 5,,,1,em0,match,scrub,in,4,0x0,,64,1,0,DF,6,tcp,60,203.0.113.5,10.0.0.5,1,22,0,S,1,,1,,mss", ParseOutcome.Skipped);
        Fw.Outcome(_f, "Nov 21 10:00:00 fw01 filterlog[1]: 5,,,1,em0,match,block,in,9,garbage", ParseOutcome.Failed);
        Fw.Outcome(_f, "Nov 21 10:00:00 fw01 sshd[1]: Accepted publickey for root from 10.0.0.12", ParseOutcome.Failed);
        Fw.Outcome(_f, "5,,,1000000103,em0,match,block,in,4,0x0,,64,12345,0,none,6,tcp,60,203.0.113.5,10.0.0.5,51234,22,0,S filterlog", ParseOutcome.Failed);
    }
}

public class NetfilterFormatTests
{
    private readonly ILogFormat _f = new NetfilterFormat();

    [Fact]
    public void Ufw_block_with_uptime_is_a_deny()
    {
        var p = Fw.Parsed(_f, "Nov 21 10:00:00 web01 kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 SRC=203.0.113.5 DST=10.0.0.5 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=54321 DF PROTO=TCP SPT=51234 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0", Fw.Plus1);
        Fw.Time(Fw.T(10, 0, 0, 1), p.Timestamp);
        Fw.Network(p, "203.0.113.5", "10.0.0.5", 51234, 22, "tcp", FirewallAction.Deny, "traffic", "UFW BLOCK", null, "web01", 60);
        Assert.Contains("in eth0", p.Url);
    }

    [Theory]
    [InlineData("Nov 21 10:00:00 web01 kernel: [UFW ALLOW] IN= OUT=eth0 SRC=10.0.0.23 DST=198.51.100.66 LEN=60 PROTO=TCP SPT=50999 DPT=4444", FirewallAction.Allow, "UFW ALLOW")]
    [InlineData("Nov 21 10:00:00 web01 kernel: [UFW LIMIT BLOCK] IN=eth0 OUT= SRC=203.0.113.9 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=1 DPT=22", FirewallAction.Deny, "UFW LIMIT BLOCK")]
    [InlineData("Nov 21 10:00:00 web01 kernel: [UFW AUDIT] IN=eth0 OUT= SRC=203.0.113.9 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=1 DPT=22", FirewallAction.Unknown, "UFW AUDIT")]
    [InlineData("Nov 21 10:00:00 web01 kernel: FINAL_REJECT: IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=1 DPT=22", FirewallAction.Reject, "FINAL_REJECT")]
    [InlineData("Nov 21 10:00:00 web01 kernel: filter_IN_public_DROP: IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=1 DPT=22", FirewallAction.Drop, "filter_IN_public_DROP")]
    [InlineData("2026-11-21T10:00:00.000000+00:00 web01 kernel: nft drop in: IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=1 DPT=22", FirewallAction.Drop, "nft drop in")]
    [InlineData("Nov 21 10:00:00 usg01 kernel: [WAN_IN-default-D]IN=eth8 OUT=eth9 SRC=203.0.113.5 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=1 DPT=22", FirewallAction.Drop, "WAN_IN-default-D")]
    [InlineData("Nov 21 10:00:00 usg01 kernel: [LAN_LOCAL-4000-A]IN=eth9 OUT= SRC=10.0.0.12 DST=10.0.0.1 LEN=60 PROTO=TCP SPT=1 DPT=22", FirewallAction.Allow, "LAN_LOCAL-4000-A")]
    [InlineData("Nov 21 10:00:00 gw kernel: Shorewall:net-fw:REJECT:IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=1 DPT=22", FirewallAction.Reject, "Shorewall:net-fw:REJECT")]
    [InlineData("Nov 21 10:00:00 OpenWrt kernel: [ 1234.5] reject wan in: IN=eth1 OUT= SRC=203.0.113.5 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=1 DPT=22", FirewallAction.Reject, "reject wan in")]
    [InlineData("Nov 21 10:00:00 web01 kernel: IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=1 DPT=22", FirewallAction.Unknown, null)]
    public void Prefixes_decide_the_action(string line, FirewallAction action, string? rule)
    {
        var p = Fw.Parsed(_f, line);
        Assert.Equal(action, p.Action);
        Assert.Equal(rule, p.RuleName);
        Fw.Time(Fw.T(10, 0, 0), p.Timestamp);
    }

    [Fact]
    public void Icmp_has_no_ports_and_ipv6_works()
    {
        var icmp = Fw.Parsed(_f, "Nov 21 10:00:00 web01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.5 LEN=84 TOS=0x00 PREC=0x00 TTL=52 ID=1 PROTO=ICMP TYPE=8 CODE=0 ID=1 SEQ=1");
        Fw.Network(icmp, "203.0.113.5", "10.0.0.5", null, null, "icmp", FirewallAction.Deny, "traffic", "UFW BLOCK", null, "web01", 84);
        Assert.Contains("type 8", icmp.Url);
        var v6 = Fw.Parsed(_f, "Nov 21 10:00:00 web01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=2001:0db8:0000:0000:0000:0000:0000:0005 DST=2001:db8::1 LEN=80 PROTO=TCP SPT=51234 DPT=22");
        Assert.Equal("2001:db8::5", v6.ClientIp);
    }

    [Fact]
    public void Missing_addresses_or_time_fail()
    {
        Fw.Outcome(_f, "Nov 21 10:00:00 web01 kernel: [UFW BLOCK] IN=eth0 OUT= PROTO=TCP SPT=1 DPT=22", ParseOutcome.Failed);
        Fw.Outcome(_f, "[12345.678901] [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.5 PROTO=TCP SPT=1 DPT=22", ParseOutcome.Failed);
        Fw.Outcome(_f, "Nov 21 10:00:00 web01 kernel: usb 1-1: new high-speed USB device", ParseOutcome.Failed);
        Fw.Outcome(_f, "Nov 21 10:00:00 web01 kernel: [UFW BLOCK] SRC=203.0.113.5 DST=10.0.0.5", ParseOutcome.Failed);
    }
}

public class WindowsFirewallFormatTests
{
    private readonly ILogFormat _f = new WindowsFirewallFormat();

    [Fact]
    public void Headers_are_skipped_and_drop_and_allow_lines_parse_with_local_time()
    {
        var parser = _f.CreateParser(Fw.Plus1);
        Assert.Equal(ParseOutcome.Skipped, parser.Parse("#Version: 1.5", out _));
        Assert.Equal(ParseOutcome.Skipped, parser.Parse("#Software: Microsoft Windows Firewall", out _));
        Assert.Equal(ParseOutcome.Skipped, parser.Parse("#Time Format: Local", out _));
        Assert.Equal(ParseOutcome.Skipped, parser.Parse("#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid", out _));

        Assert.Equal(ParseOutcome.Parsed, parser.Parse("2026-11-21 10:00:00 DROP TCP 203.0.113.5 10.0.0.5 51234 3389 52 S 1234567 0 64240 - - - RECEIVE 4", out var drop));
        Fw.Time(Fw.T(10, 0, 0, 1), drop!.Timestamp);
        Fw.Network(drop, "203.0.113.5", "10.0.0.5", 51234, 3389, "tcp", FirewallAction.Drop, "traffic", null, null, null, 52);
        Assert.Contains("RECEIVE", drop.Url);

        Assert.Equal(ParseOutcome.Parsed, parser.Parse("2026-11-21 10:00:05 ALLOW UDP 10.0.0.5 198.51.100.53 53000 53 0 - - - - - - - SEND 1234", out var allow));
        Fw.Network(allow!, "10.0.0.5", "198.51.100.53", 53000, 53, "udp", FirewallAction.Allow, "traffic", null, null, null, 0);
        Assert.Contains("SEND", allow!.Url);
    }

    [Fact]
    public void Without_header_the_default_order_is_used_also_without_pid()
    {
        var p = Fw.Parsed(_f, "2026-11-21 10:00:00 ALLOW ICMP 10.0.0.12 10.0.0.1 - - 60 - - - - 8 0 - SEND");
        Fw.Network(p, "10.0.0.12", "10.0.0.1", null, null, "icmp", FirewallAction.Allow, "traffic", null, null, null, 60);
        Assert.Contains("icmp type 8", p.Url);
    }

    [Fact]
    public void Custom_field_order_and_utc_time_format()
    {
        var parser = _f.CreateParser(Fw.Plus1);
        Assert.Equal(ParseOutcome.Skipped, parser.Parse("#Time Format: UTC", out _));
        Assert.Equal(ParseOutcome.Skipped, parser.Parse("#Fields: date time action src-ip src-port dst-ip dst-port protocol path", out _));
        Assert.Equal(ParseOutcome.Parsed, parser.Parse("2026-11-21 10:00:00 DROP 203.0.113.5 51234 10.0.0.5 445 TCP RECEIVE", out var p));
        Fw.Time(Fw.T(10, 0, 0), p!.Timestamp);
        Fw.Network(p, "203.0.113.5", "10.0.0.5", 51234, 445, "tcp", FirewallAction.Drop, "traffic");
    }

    [Fact]
    public void Lost_events_marker_is_skipped_and_foreign_lines_fail()
    {
        Fw.Outcome(_f, "2026-11-21 10:00:00 INFO-EVENTS-LOST - - - - - - - - - - - - 12 - -", ParseOutcome.Skipped);
        Fw.Outcome(_f, "2026-11-21 10:00:00 BLOCK TCP 203.0.113.5 10.0.0.5 1 2 3 - - - - - - - RECEIVE 4", ParseOutcome.Failed);
        Fw.Outcome(_f, "2026-11-21 10:00:00 DROP TCP 203.0.113 10.0.0.5 1 2 3 - - - - - - - RECEIVE 4", ParseOutcome.Failed);
        Fw.Outcome(_f, "#Some other comment", ParseOutcome.Failed);
        Fw.Outcome(_f, "#Fields: a b c", ParseOutcome.Failed);
    }
}

public class AwsVpcFlowFormatTests
{
    private readonly ILogFormat _f = new AwsVpcFlowFormat();

    [Fact]
    public void Default_v2_reject_and_accept()
    {
        var p = Fw.Parsed(_f, "2 123456789012 eni-0a1b2c3d4e5f67890 203.0.113.5 10.0.0.5 51234 22 6 1 60 1795255200 1795255260 REJECT OK", Fw.Plus1);
        Fw.Time(Fw.T(10, 0, 0), p.Timestamp);   // epoch = UTC whatever the file default
        Fw.Network(p, "203.0.113.5", "10.0.0.5", 51234, 22, "tcp", FirewallAction.Reject, "traffic", null, null, "eni-0a1b2c3d4e5f67890", 60);

        var a = Fw.Parsed(_f, "2 123456789012 eni-0a1b2c3d4e5f67890 10.0.0.23 198.51.100.66 50999 4444 6 40 18000 1795256100 1795256160 ACCEPT OK");
        Fw.Network(a, "10.0.0.23", "198.51.100.66", 50999, 4444, "tcp", FirewallAction.Allow, "traffic", null, null, "eni-0a1b2c3d4e5f67890", 18000);
    }

    [Fact]
    public void Task_example_epoch_is_2025()
    {
        var p = Fw.Parsed(_f, "2 123456789012 eni-0a1b2c3d4e5f67890 203.0.113.5 10.0.0.5 51234 22 6 1 60 1763719200 1763719260 REJECT OK");
        Fw.Time(new DateTimeOffset(2025, 11, 21, 10, 0, 0, TimeSpan.Zero), p.Timestamp);
    }

    [Fact]
    public void Header_and_custom_field_order()
    {
        var parser = _f.CreateParser(Fw.Utc);
        Assert.Equal(ParseOutcome.Skipped, parser.Parse("${version} ${vpc-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${start} ${action} ${flow-direction} ${log-status}", out _));
        Assert.Equal(ParseOutcome.Parsed, parser.Parse("5 vpc-0123456789abcdef0 203.0.113.5 10.0.0.5 51234 3389 6 1795255200 REJECT ingress OK", out var p));
        Fw.Network(p!, "203.0.113.5", "10.0.0.5", 51234, 3389, "tcp", FirewallAction.Reject, "traffic");
        Assert.Contains("ingress", p!.Url);
        // a line in the old default layout no longer fits the declared columns
        Assert.Equal(ParseOutcome.Failed, parser.Parse("2 123456789012 eni-0a1b2c3d4e5f67890 203.0.113.5 10.0.0.5 51234 22 6 1 60 1795255200 1795255260 REJECT OK", out _));
    }

    [Fact]
    public void Nodata_is_skipped_and_icmp_has_no_ports_and_garbage_fails()
    {
        Fw.Outcome(_f, "2 123456789012 eni-0a1b2c3d4e5f67891 - - - - - - - 1795255200 1795255260 - NODATA", ParseOutcome.Skipped);
        Fw.Outcome(_f, "2 123456789012 eni-0a1b2c3d4e5f67891 - - - - - - - 1795255200 1795255260 - SKIPDATA", ParseOutcome.Skipped);
        var icmp = Fw.Parsed(_f, "2 123456789012 eni-0a1b2c3d4e5f67890 203.0.113.5 10.0.0.5 0 0 1 1 84 1795255200 1795255260 REJECT OK");
        Assert.Null(icmp.SourcePort);
        Assert.Equal("icmp", icmp.Transport);
        Fw.Outcome(_f, "2 123456789012 eni-0a1b2c3d4e5f67890 203.0.113.5 10.0.0.5 51234 22 6 1 60 notatime 1795255260 REJECT OK", ParseOutcome.Failed);
        Fw.Outcome(_f, "2 123456789012 eni-0a1b2c3d4e5f67890 203.0.113.5 10.0.0.5 51234 22 6 1 60 1795255200 1795255260 MAYBE OK", ParseOutcome.Failed);
        Fw.Outcome(_f, "x 123456789012 eni-0a1b2c3d4e5f67890 203.0.113.5 10.0.0.5 51234 22 6 1 60 1795255200 1795255260 REJECT OK", ParseOutcome.Failed);
    }
}

public class JuniperSrxFormatTests
{
    private readonly ILogFormat _f = new JuniperSrxFormat();

    [Fact]
    public void Text_session_denied()
    {
        var p = Fw.Parsed(_f, "Nov 21 10:00:00 srx01 RT_FLOW: RT_FLOW_SESSION_DENY: session denied 203.0.113.5/51234->10.0.0.5/22 0x0 junos-ssh 6(0) default-deny(global) untrust trust UNKNOWN UNKNOWN N/A(N/A) ge-0/0/0.0 UNKNOWN policy deny", Fw.Plus1);
        Fw.Time(Fw.T(10, 0, 0, 1), p.Timestamp);
        Fw.Network(p, "203.0.113.5", "10.0.0.5", 51234, 22, "tcp", FirewallAction.Deny, "traffic", "default-deny", null, "srx01");
        Assert.Contains("policy deny", p.Url);
        Assert.Contains("untrust -> trust", p.Url);
    }

    [Fact]
    public void Text_session_created_and_closed_are_allows()
    {
        var created = Fw.Parsed(_f, "Nov 21 10:00:00 srx01 RT_FLOW: RT_FLOW_SESSION_CREATE: session created 203.0.113.5/51234->10.0.0.5/443 0x0 junos-https 203.0.113.5/51234->10.0.0.5/443 0x0 N/A N/A N/A N/A 6 allow-web untrust trust 12345 N/A(N/A) ge-0/0/0.0 UNKNOWN UNKNOWN UNKNOWN N/A N/A -1 N/A N/A N/A");
        Fw.Network(created, "203.0.113.5", "10.0.0.5", 51234, 443, "tcp", FirewallAction.Allow, "traffic", "allow-web", null, "srx01");
        var closed = Fw.Parsed(_f, Fw.Sample("juniper-srx.log")[1]);
        Fw.Network(closed, "198.51.100.10", "10.0.0.20", 50000, 443, "tcp", FirewallAction.Allow, "traffic", "allow-web", null, "srx01", 1200 + 4096);
        Assert.Contains("TCP FIN", closed.Url);
        Fw.Time(Fw.T(10, 0, 5), closed.Timestamp);
    }

    [Fact]
    public void Structured_data_mode()
    {
        var p = Fw.Parsed(_f, "<14>1 2026-11-21T10:00:00.000+01:00 srx01 RT_FLOW - RT_FLOW_SESSION_DENY [junos@2636.1.1.1.2.129 source-address=\"203.0.113.5\" source-port=\"51234\" destination-address=\"10.0.0.5\" destination-port=\"22\" connection-tag=\"0\" service-name=\"junos-ssh\" protocol-id=\"6\" icmp-type=\"0\" policy-name=\"default-deny\" source-zone-name=\"untrust\" destination-zone-name=\"trust\" application=\"UNKNOWN\" nested-application=\"UNKNOWN\" username=\"N/A\" roles=\"N/A\" packet-incoming-interface=\"ge-0/0/0.0\" encrypted=\"UNKNOWN\" reason=\"policy reject\"]");
        Fw.Time(Fw.T(10, 0, 0, 1), p.Timestamp);
        Fw.Network(p, "203.0.113.5", "10.0.0.5", 51234, 22, "tcp", FirewallAction.Reject, "traffic", "default-deny", null, "srx01");

        var create = Fw.Parsed(_f, Fw.Sample("juniper-srx.log").First(l => l.Contains("junos@")));
        Fw.Network(create, "203.0.113.9", "10.0.0.30", 42000, 22, "tcp", FirewallAction.Allow, "traffic", "allow-ssh-admin", null, "srx01");
    }

    [Fact]
    public void Idp_attack_is_a_threat_with_epoch_time()
    {
        var p = Fw.Parsed(_f, "Nov 21 09:00:00 srx01 RT_IDP: IDP_ATTACK_LOG_EVENT: IDP: at 1795255200, SIG Attack log <203.0.113.5/51234->10.0.0.5/80> for TCP protocol and service HTTP application NONE by rule 1 of rulebase IPS in policy Recommended. attack: id=1234, repeat=0, action=DROP, threat-severity=HIGH, name=HTTP:SQL:INJ:GENERIC, NAT <0.0.0.0:0->0.0.0.0:0>, time-elapsed=0, inbytes=0", Fw.Plus1);
        Fw.Time(Fw.T(10, 0, 0), p.Timestamp);
        Fw.Network(p, "203.0.113.5", "10.0.0.5", 51234, 80, "tcp", FirewallAction.Drop, "threat", "Recommended", "HTTP:SQL:INJ:GENERIC", "srx01");
        Assert.Contains("HIGH", p.Url);
        var detected = Fw.Parsed(_f, Fw.Sample("juniper-srx.log").Single(l => l.Contains("TRAVERSE")));
        Assert.Equal(FirewallAction.Alert, detected.Action);
    }

    [Fact]
    public void Screen_events_are_threats()
    {
        var scan = Fw.Parsed(_f, "Nov 21 10:00:00 srx01 RT_SCREEN: RT_SCREEN_TCP: TCP port scan! source: 203.0.113.5:51234, destination: 10.0.0.5:22, zone name: untrust, interface name: ge-0/0/0.0, action: drop");
        Fw.Network(scan, "203.0.113.5", "10.0.0.5", 51234, 22, "tcp", FirewallAction.Drop, "threat", "screen untrust", "TCP port scan", "srx01");
        var spoof = Fw.Parsed(_f, "Nov 21 10:00:00 srx01 RT_SCREEN: RT_SCREEN_IP: IP spoofing! source: 203.0.113.5, destination: 10.0.0.5, protocol-id: 17, zone name: untrust, interface name: ge-0/0/0.0, action: drop");
        Fw.Network(spoof, "203.0.113.5", "10.0.0.5", null, null, "udp", FirewallAction.Drop, "threat", "screen untrust", "IP spoofing", "srx01");
        var flood = Fw.Parsed(_f, Fw.Sample("juniper-srx.log").Single(l => l.Contains("ICMP flood")));
        Fw.Network(flood, "192.0.2.44", "10.0.0.20", null, null, "icmp", FirewallAction.Drop, "threat", "screen untrust", "ICMP flood", "srx01");
    }

    [Fact]
    public void Sshd_login_failed_is_auth_deny()
    {
        var p = Fw.Parsed(_f, "Nov 21 10:00:00 srx01 sshd[2101]: SSHD_LOGIN_FAILED: Login failed for user 'root' from host '203.0.113.9'");
        Fw.Network(p, "203.0.113.9", null, null, null, null, FirewallAction.Deny, "auth", null, null, "srx01");
        Assert.Contains("root", p.Url);
    }

    [Fact]
    public void Other_junos_lines_are_skipped_and_foreign_lines_fail()
    {
        Fw.Outcome(_f, "Nov 21 10:00:00 srx01 mgd[3301]: UI_COMMIT: User 'admin' requested 'commit' operation (comment: none)", ParseOutcome.Skipped);
        Fw.Outcome(_f, "Nov 21 10:00:00 srx01 mib2d[1702]: SNMP_TRAP_LINK_UP: ifIndex 528, ifAdminStatus up(1)", ParseOutcome.Skipped);
        Fw.Outcome(_f, "Nov 21 10:00:00 srx01 RT_FLOW: RT_FLOW_SESSION_DENY: session denied garbage", ParseOutcome.Failed);
        Fw.Outcome(_f, "Nov 21 10:00:00 host app: the RT_ tag is just text here", ParseOutcome.Failed);
        Fw.Outcome(_f, "Nov 21 10:00:00 host sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2", ParseOutcome.Failed);
    }
}

public class WatchGuardFormatTests
{
    private readonly ILogFormat _f = new WatchGuardFormat();

    [Fact]
    public void Deny_with_policy_in_parentheses()
    {
        var p = Fw.Parsed(_f, "Nov 21 10:00:00 FBX-M370 801001AB02 firewall: msg_id=\"3000-0148\" Deny 1-Trusted 0-External 60 tcp 20 64 203.0.113.5 10.0.0.5 51234 22 offset 10 S 123456 win 64240 (Unhandled External Packet-00)", Fw.Plus1);
        Fw.Time(Fw.T(10, 0, 0, 1), p.Timestamp);
        Fw.Network(p, "203.0.113.5", "10.0.0.5", 51234, 22, "tcp", FirewallAction.Deny, "traffic", "Unhandled External Packet-00", null, "FBX-M370", 60);
        Assert.Contains("3000-0148", p.Url);
    }

    [Fact]
    public void Allow_and_short_form_without_lengths()
    {
        var p = Fw.Parsed(_f, "Nov 21 10:00:00 FBX-M370 801001AB02 firewall: msg_id=\"3000-0151\" Allow 1-Trusted 0-External 52 tcp 20 128 10.0.0.12 198.51.100.7 53312 443 offset 8 S 123 win 64240 (Outgoing-proxy-00)");
        Fw.Network(p, "10.0.0.12", "198.51.100.7", 53312, 443, "tcp", FirewallAction.Allow, "traffic", "Outgoing-proxy-00", null, "FBX-M370", 52);
        var s = Fw.Parsed(_f, "Nov 21 10:00:00 FBX-M370 801001AB02 firewall: msg_id=\"3000-0151\" Allow 1-Trusted 0-External udp 10.0.0.12 198.51.100.53 53000 53 (DNS-proxy-00)");
        Fw.Network(s, "10.0.0.12", "198.51.100.53", 53000, 53, "udp", FirewallAction.Allow, "traffic", "DNS-proxy-00", null, "FBX-M370");
    }

    [Fact]
    public void Ips_signature_is_a_threat()
    {
        var sample = Fw.Sample("watchguard.log");
        var p = Fw.Parsed(_f, sample.Single(l => l.Contains("SQL injection")));
        Fw.Network(p, "192.0.2.44", "10.0.0.20", 43001, 80, "tcp", FirewallAction.Deny, "threat", "HTTP-proxy-00", "WEB SQL injection attempt -33", "FBX-M370", 420);
        var alert = Fw.Parsed(_f, sample.Single(l => l.Contains("Traversal")));
        Assert.Equal(FirewallAction.Alert, alert.Action);
    }

    [Fact]
    public void Authentication_rejected_and_accepted()
    {
        var p = Fw.Parsed(_f, "Nov 21 10:00:00 FBX-M370 801001AB02 admd: msg_id=\"3E00-0002\" Authentication of Firebox user [admin@Firebox-DB] from 203.0.113.9 was rejected, password is incorrect");
        Fw.Network(p, "203.0.113.9", null, null, null, null, FirewallAction.Deny, "auth", null, null, "FBX-M370");
        Assert.Contains("admin@Firebox-DB", p.Url);
        var ok = Fw.Parsed(_f, Fw.Sample("watchguard.log").Single(l => l.Contains("was accepted")));
        Assert.Equal(FirewallAction.Allow, ok.Action);
    }

    [Fact]
    public void Other_fireware_messages_skipped_and_foreign_lines_fail()
    {
        Fw.Outcome(_f, "Nov 21 10:00:00 FBX-M370 801001AB02 loggerd: msg_id=\"3D00-0001\" Archived log file /var/log/traffic.log which reached max size", ParseOutcome.Skipped);
        Fw.Outcome(_f, "Nov 21 10:00:00 FBX-M370 801001AB02 firewall: msg_id=\"nothex!\" Deny", ParseOutcome.Failed);
        Fw.Outcome(_f, "Nov 21 10:00:00 FBX-M370 firewall: Deny 1-Trusted 0-External tcp 203.0.113.5 10.0.0.5 1 22", ParseOutcome.Failed);
        Fw.Outcome(_f, "date=2026-11-21 time=10:00:00 devname=\"fw\" msg_id=\"x\"", ParseOutcome.Failed);
    }
}

public class MikroTikFormatTests
{
    private readonly ILogFormat _f = new MikroTikFormat();

    [Fact]
    public void Drop_with_prefix_and_topics()
    {
        var p = Fw.Parsed(_f, "Nov 21 10:00:00 router1 firewall,info DROP-WAN input: in:ether1 out:(unknown 0), src-mac 00:11:22:33:44:55, proto TCP (SYN), 203.0.113.5:51234->10.0.0.5:22, len 60", Fw.Plus1);
        Fw.Time(Fw.T(10, 0, 0, 1), p.Timestamp);
        Fw.Network(p, "203.0.113.5", "10.0.0.5", 51234, 22, "tcp", FirewallAction.Drop, "traffic", "DROP-WAN", null, "router1", 60);
        Assert.Contains("ether1", p.Url);
    }

    [Fact]
    public void Accept_forward_and_no_prefix_uses_chain()
    {
        var a = Fw.Parsed(_f, "Nov 21 10:00:00 router1 firewall,info ACCEPT-LAN forward: in:bridge out:ether1, connection-state:new src-mac 00:11:22:33:44:55, proto UDP, 10.0.0.23:50999->198.51.100.66:4444, NAT (10.0.0.23:50999->198.51.100.1:50999)->198.51.100.66:4444, len 76");
        Fw.Network(a, "10.0.0.23", "198.51.100.66", 50999, 4444, "udp", FirewallAction.Allow, "traffic", "ACCEPT-LAN", null, "router1", 76);
        var n = Fw.Parsed(_f, "Nov 21 10:00:00 router1 firewall,info input: in:ether1 out:(unknown 0), src-mac 00:11:22:33:44:55, proto TCP (SYN), 203.0.113.5:51234->10.0.0.5:22, len 60");
        Fw.Network(n, "203.0.113.5", "10.0.0.5", 51234, 22, "tcp", FirewallAction.Unknown, "traffic", "input", null, "router1", 60);
        var noTopics = Fw.Parsed(_f, "Nov 21 10:00:00 router1 REJECT-WAN input: in:ether1 out:(unknown 0), proto TCP (SYN), 203.0.113.5:51234->10.0.0.5:23, len 60");
        Assert.Equal(FirewallAction.Reject, noTopics.Action);
    }

    [Fact]
    public void Icmp_and_ipv6()
    {
        var icmp = Fw.Parsed(_f, "Nov 21 10:00:00 router1 firewall,info DROP-WAN input: in:ether1 out:(unknown 0), src-mac 00:11:22:33:44:55, proto ICMP (type 8, code 0), 203.0.113.5->10.0.0.5, len 84");
        Fw.Network(icmp, "203.0.113.5", "10.0.0.5", null, null, "icmp", FirewallAction.Drop, "traffic", "DROP-WAN", null, "router1", 84);
        Assert.Contains("type 8, code 0", icmp.Url);
        var v6 = Fw.Parsed(_f, "Nov 21 10:00:00 router1 firewall,info DROP-WAN6 input: in:ether1 out:(unknown 0), src-mac 00:11:22:33:44:55, proto TCP (SYN), [2001:db8::5]:51234->[2001:db8::1]:22, len 80");
        Fw.Network(v6, "2001:db8::5", "2001:db8::1", 51234, 22, "tcp", FirewallAction.Drop, "traffic", "DROP-WAN6", null, "router1", 80);
        var v6Icmp = Fw.Parsed(_f, "Nov 21 10:00:00 router1 firewall,info DROP-WAN6 input: in:ether1 out:(unknown 0), proto ICMP (type 128, code 0), 2001:db8::5->2001:db8::1, len 64");
        Assert.Equal("2001:db8::5", v6Icmp.ClientIp);
    }

    [Fact]
    public void Login_failure_and_success()
    {
        var p = Fw.Parsed(_f, "Nov 21 10:00:00 router1 system,error,critical login failure for user admin from 203.0.113.9 via ssh");
        Fw.Network(p, "203.0.113.9", null, null, null, null, FirewallAction.Deny, "auth", null, null, "router1");
        Assert.Contains("via ssh", p.Url);
        var ok = Fw.Parsed(_f, "Nov 21 10:00:00 router1 system,info,account user admin logged in from 10.0.0.12 via winbox");
        Fw.Network(ok, "10.0.0.12", null, null, null, null, FirewallAction.Allow, "auth", null, null, "router1");
    }

    [Fact]
    public void Other_topics_skipped_and_foreign_lines_fail()
    {
        Fw.Outcome(_f, "Nov 21 10:00:00 router1 system,info item changed by admin", ParseOutcome.Skipped);
        Fw.Outcome(_f, "Nov 21 10:00:00 router1 dhcp,info dhcp1 assigned 10.0.0.77 to 00:00:5E:00:53:0A", ParseOutcome.Skipped);
        Fw.Outcome(_f, "Nov 21 10:00:00 router1 system,info,account user admin logged out from 10.0.0.12 via winbox", ParseOutcome.Skipped);
        Fw.Outcome(_f, "Nov 21 10:00:00 router1 firewall,info DROP input: in:ether1 out:(unknown 0), proto TCP (SYN), garbage, len 60", ParseOutcome.Failed);
        Fw.Outcome(_f, "Nov 21 10:00:00 host something,else entirely", ParseOutcome.Failed);
    }
}

/// <summary>Cross-format behaviour: detection, foreign lines, mixed files, sample stories, speed.</summary>
public class FirewallPositionalFormatTests
{
    public static TheoryData<string, string> Samples()
    {
        var data = new TheoryData<string, string>();
        foreach (var (id, file) in Fw.SampleFiles)
            data.Add(id, file);
        return data;
    }

    [Fact]
    public void All_nine_formats_are_registered_as_firewall_formats()
    {
        foreach (var (id, _) in Fw.SampleFiles)
        {
            var f = Fw.Format(id);
            Assert.Equal(LogSource.Firewall, f.Source);
            Assert.Equal(100, f.Specificity);
            Assert.False(string.IsNullOrWhiteSpace(f.DisplayName));
        }
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void Detector_picks_the_right_format_for_each_sample(string id, string file)
    {
        var detection = LogFormatDetector.Detect(Fw.Sample(file), Fw.Utc);
        Assert.Equal(id, detection.Format?.Id);
        Assert.True(detection.Ratio >= 0.9, $"{id}: only {detection.Parsed}/{detection.Considered} lines read");
    }

    [Fact]
    public void Detector_still_picks_combined_for_the_access_log()
    {
        var sample = Fw.AccessLog().Take(LogFormatDetector.SampleLines).ToList();
        Assert.Equal(WebAccessLogFormat.FormatId, LogFormatDetector.Detect(sample, Fw.Utc).Format?.Id);
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void Every_sample_line_is_parsed_or_skipped_by_its_own_format(string id, string file)
    {
        var parser = Fw.Format(id).CreateParser(Fw.Utc);
        foreach (var line in Fw.Sample(file))
        {
            var outcome = parser.Parse(line, out var result);
            Assert.True(outcome != ParseOutcome.Failed, $"{id}: failed on {line}");
            if (outcome == ParseOutcome.Parsed)
            {
                Assert.True(result!.ClientIp != "-" || result.DestinationIp is not null);
                Assert.Equal(2026, result.Timestamp.Year);
            }
        }
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void Each_format_fails_on_other_vendors_and_on_access_logs(string id, string ownFile)
    {
        var format = Fw.Format(id);
        var foreign = Fw.SampleFiles.Where(s => s.File != ownFile).SelectMany(s => Fw.Sample(s.File)).Concat(Fw.AccessLog());
        foreach (var line in foreign)
        {
            var outcome = format.CreateParser(Fw.Utc).Parse(line, out var result);
            Assert.True(outcome == ParseOutcome.Failed, $"{id}: {outcome} on foreign line {line}");
            Assert.Null(result);
        }
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void Samples_tell_the_story_the_rules_look_for(string id, string file)
    {
        var parser = Fw.Format(id).CreateParser(Fw.Utc);
        var events = new List<ParsedLine>();
        foreach (var line in Fw.Sample(file))
            if (parser.Parse(line, out var r) == ParseOutcome.Parsed)
                events.Add(r!);

        Assert.InRange(Fw.Sample(file).Length, 30, 80);
        // port scan: one source, 20+ destination ports within a minute
        var scan = events.Where(e => e.ClientIp == "203.0.113.5" && e.DestinationPort is not null).ToList();
        Assert.True(scan.Select(e => e.DestinationPort).Distinct().Count() >= 20, $"{id}: no port scan");
        Assert.True(Fw.MaxInWindow(scan.Select(e => e.Timestamp), TimeSpan.FromMinutes(1)) >= 20, $"{id}: scan too slow");
        // brute force: 20+ connections to 22 / 3389 within 5 minutes
        var brute = events.Where(e => e.ClientIp == "203.0.113.9" && e.DestinationPort is 22 or 3389).ToList();
        Assert.True(Fw.MaxInWindow(brute.Select(e => e.Timestamp), TimeSpan.FromMinutes(5)) >= 20, $"{id}: no brute force");
        // inside host to port 4444
        Assert.Contains(events, e => e.DestinationPort == 4444 && e.ClientIp.StartsWith("10.", StringComparison.Ordinal));
        // allowed normal traffic
        Assert.True(events.Count(e => e.Action == FirewallAction.Allow) >= 5);
        // only documentation / private addresses
        foreach (var e in events)
            foreach (var ip in new[] { e.ClientIp, e.DestinationIp }.Where(i => i is not null && i != "-"))
                Assert.False(IpAddressPolicy.IsPublic(ip!), $"{id}: public address {ip}");
    }

    [Theory]
    [InlineData("pfsense", "pfsense.log")]
    [InlineData("aws-vpc-flow", "aws-vpc-flow.log")]
    [InlineData("netfilter", "iptables-ufw.log")]
    public void Sweep_samples_contain_a_network_sweep_on_445(string id, string file)
    {
        var parser = Fw.Format(id).CreateParser(Fw.Utc);
        var sweep = Fw.Sample(file).Select(l => parser.Parse(l, out var r) == ParseOutcome.Parsed ? r : null)
            .Where(e => e is { ClientIp: "198.51.100.23", DestinationPort: 445 }).ToList();
        Assert.True(sweep.Select(e => e!.DestinationIp).Distinct().Count() >= 20);
        Assert.True(sweep.Max(e => e!.Timestamp) - sweep.Min(e => e!.Timestamp) <= TimeSpan.FromMinutes(2));
    }

    [Fact]
    public void Threat_and_auth_events_exist_where_the_vendor_logs_them()
    {
        foreach (var (id, file) in Fw.SampleFiles.Where(s => s.Id is "paloalto" or "cisco-asa" or "juniper-srx" or "watchguard"))
        {
            var parser = Fw.Format(id).CreateParser(Fw.Utc);
            var events = Fw.Sample(file).Select(l => parser.Parse(l, out var r) == ParseOutcome.Parsed ? r : null).Where(e => e is not null).ToList();
            Assert.True(events.Count(e => e!.EventType == "threat") >= 2, id);
            Assert.True(events.Count(e => e!.EventType == "auth" && e.Action == FirewallAction.Deny) >= 3, id);
        }
        var mt = Fw.Format("mikrotik").CreateParser(Fw.Utc);
        Assert.True(Fw.Sample("mikrotik.log").Count(l => mt.Parse(l, out var r) == ParseOutcome.Parsed && r!.EventType == "auth" && r.Action == FirewallAction.Deny) >= 3);
    }

    [Fact]
    public void Mixed_cisco_and_iptables_file_reads_both()
    {
        var asa = Fw.Sample("cisco-asa.log");
        var ufw = Fw.Sample("iptables-ufw.log");
        var mixed = asa.Zip(ufw, (a, b) => new[] { a, b }).SelectMany(x => x).ToList();
        var detection = LogFormatDetector.Detect(mixed.Take(LogFormatDetector.SampleLines).ToList(), Fw.Utc);
        Assert.NotNull(detection.Format);

        var parser = new MultiFormatParser(detection.Format!, Fw.Utc);
        var parsed = 0;
        var failed = 0;
        foreach (var line in mixed)
        {
            var outcome = parser.Parse(line, out _);
            if (outcome == ParseOutcome.Parsed) parsed++;
            if (outcome == ParseOutcome.Failed) failed++;
        }
        Assert.Equal(0, failed);
        Assert.True(parsed > 100);
        Assert.Contains("Cisco ASA / FTD", parser.UsedFormats.Keys);
        Assert.Contains("Linux netfilter (iptables / UFW / firewalld / nftables)", parser.UsedFormats.Keys);
        var text = parser.Describe();
        Assert.Contains("Cisco ASA / FTD", text);
        Assert.Contains("Linux netfilter", text);
        Assert.Contains(" + ", text);
    }

    [Theory]
    [InlineData("pfsense", "pfsense.log")]
    [InlineData("cisco-asa", "cisco-asa.log")]
    public void Parses_100k_lines_in_a_few_seconds(string id, string file)
    {
        var lines = Fw.Sample(file);
        var parser = Fw.Format(id).CreateParser(Fw.Utc);
        var sw = Stopwatch.StartNew();
        var parsed = 0;
        for (var i = 0; i < 100_000; i++)
            if (parser.Parse(lines[i % lines.Length], out _) == ParseOutcome.Parsed)
                parsed++;
        sw.Stop();
        Assert.True(parsed > 90_000);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"{id}: {sw.ElapsedMilliseconds} ms");
    }

    [Fact]
    public void Parsers_never_throw_on_hostile_input()
    {
        var junk = new[]
        {
            "", " ", "\t", "<", "<1>", "<999999999999>1 x", "%ASA-", "%ASA-4-106023:", ",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,",
            "\"\"\"\"\"", "SRC= DST= IN=", "msg_id=\"", "msg_id=\"1-1\"", ": in:", "#Fields:", "version srcaddr dstaddr",
            "Nov 21 10:00:00 h firewall,info x: in: proto ", "Nov 21 10:00:00 h RT_FLOW: RT_FLOW_SESSION_CLOSE: session closed : ->",
            new string('[', 5000), new string('%', 5000) + "ASA-4-106023: Deny tcp src " + new string('/', 5000),
            "Nov 21 10:00:00 h RT_IDP: IDP_ATTACK_LOG_EVENT: <" + new string('-', 3000) + ">",
            "Nov 21 10:00:00 h filterlog: " + string.Join(',', Enumerable.Repeat("4", 3000))
        };
        foreach (var (id, _) in Fw.SampleFiles)
        {
            var parser = Fw.Format(id).CreateParser(Fw.Utc);
            foreach (var line in junk)
            {
                var ex = Record.Exception(() => parser.Parse(line, out _));
                Assert.Null(ex);
            }
        }
    }
}
