using System.Diagnostics;
using System.Globalization;
using System.Text;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.Services.LogFormats;

namespace LogAnalyzer.Tests;

/// <summary>
/// Firewall formats checked against the vendors' public documentation (2026-11-25, URL next to each test) and
/// behaviour of the parsers on attacker-controlled log text (spoofing).
/// </summary>
public class FirewallFormatVerificationTests
{
    internal static readonly LogParseContext Ctx = new(new DateTimeOffset(2026, 11, 25, 12, 0, 0, TimeSpan.Zero), TimeSpan.Zero);

    private static ParseOutcome Outcome(string formatId, string line, out ParsedLine? p) =>
        LogFormatRegistry.Find(formatId)!.CreateParser(Ctx).Parse(line, out p);

    private static ParsedLine Parse(string formatId, string line)
    {
        Assert.Equal(ParseOutcome.Parsed, Outcome(formatId, line, out var p));
        return p!;
    }

    // ------------------------------------------------------------------ Cisco ASA / FTD
    // https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-302003-to-342008.html

    private const string Asa = "Nov 21 2026 10:00:00 asa01 : ";

    [Theory]
    [InlineData("inbound", "203.0.113.5", "10.0.0.5", 51234, 80)]
    [InlineData("outbound", "10.0.0.5", "203.0.113.5", 80, 51234)]
    public void Asa_built_messages_with_identity_firewall_users_keep_direction_and_ports(string dir, string src, string dst, int sport, int dport)
    {
        // idfw_user follows the address without a space, "(user)" may follow at the end
        var p = Parse("cisco-asa", Asa + $"%ASA-6-302013: Built {dir} TCP connection 77 for outside:203.0.113.5/51234 (203.0.113.5/51234)(LOCAL\\john doe) to inside:10.0.0.5/80 (198.51.100.5/80) (bob)");
        Assert.Equal((src, dst, sport, dport), (p.ClientIp, p.DestinationIp!, p.SourcePort!.Value, p.DestinationPort!.Value));
        p = Parse("cisco-asa", Asa + $"%ASA-6-302015: Built {dir} UDP connection 78 for outside:203.0.113.5/51234(LOCAL\\john) (203.0.113.5/51234) to inside:10.0.0.5/80(LOCAL\\x) (198.51.100.5/80)");
        Assert.Equal((src, dst, sport, dport), (p.ClientIp, p.DestinationIp!, p.SourcePort!.Value, p.DestinationPort!.Value));
    }

    [Fact]
    public void Asa_probe_connections_are_read()
    {
        var p = Parse("cisco-asa", Asa + "%ASA-6-302013: Built inbound Probe TCP connection 77 for outside:203.0.113.5/51234 (203.0.113.5/51234) to inside:10.0.0.5/80 (10.0.0.5/80)");
        Assert.Equal("203.0.113.5", p.ClientIp);
    }

    [Fact]
    public void Asa_teardown_takes_the_direction_of_its_built_message()
    {
        // attacker port 1025 < service port 4444: without the connection id the victim would become the source
        var parser = LogFormatRegistry.Find("cisco-asa")!.CreateParser(Ctx);
        Assert.Equal(ParseOutcome.Parsed, parser.Parse(Asa + "%ASA-6-302013: Built inbound TCP connection 900 for outside:203.0.113.5/1025 (203.0.113.5/1025) to inside:10.0.0.5/4444 (10.0.0.5/4444)", out _));
        Assert.Equal(ParseOutcome.Parsed, parser.Parse(Asa + "%ASA-6-302014: Teardown TCP connection 900 for outside:203.0.113.5/1025 to inside:10.0.0.5/4444 duration 0:00:05 bytes 1234 TCP FINs from outside", out var p));
        Assert.Equal("203.0.113.5", p!.ClientIp);
        Assert.Equal(4444, p.DestinationPort);
        Assert.Equal(1234, p.ResponseSize);

        Assert.Equal(ParseOutcome.Parsed, parser.Parse(Asa + "%ASA-6-302015: Built outbound UDP connection 901 for outside:198.51.100.9/53 (198.51.100.9/53) to inside:10.0.0.5/49152 (10.0.0.5/49152)", out _));
        Assert.Equal(ParseOutcome.Parsed, parser.Parse(Asa + "%ASA-6-302016: Teardown UDP connection 901 for outside:198.51.100.9/53 to inside:10.0.0.5/49152 duration 0:00:05 bytes 99", out p));
        Assert.Equal("10.0.0.5", p!.ClientIp);
        Assert.Equal(53, p.DestinationPort);
    }

    [Theory]
    [InlineData("%ASA-6-302020: Built outbound ICMP connection for faddr 198.51.100.7/0(LOCAL\\a b) gaddr 10.0.0.250/7(x) laddr 10.0.0.250/7(LOCAL\\c) (carol) type 8 code 0", "10.0.0.250")]
    [InlineData("%ASA-6-302020: Built inbound ICMP connection for faddr 198.51.100.7/7 gaddr 10.0.0.250/0 laddr 10.0.0.250/0 (carol) type 8 code 0", "198.51.100.7")]
    [InlineData("%ASA-6-302020: Built ICMP connection for faddr 198.51.100.7/0 gaddr 10.0.0.250/0 laddr 10.0.0.250/0", "198.51.100.7")]
    // teardown has no direction word: the side with the ICMP identifier sent the request
    [InlineData("%ASA-6-302021: Teardown ICMP connection for faddr 198.51.100.7/0 gaddr 10.0.0.250/7 laddr 10.0.0.250/7 type 8 code 0", "10.0.0.250")]
    [InlineData("%ASA-6-302021: Teardown ICMP connection for faddr 198.51.100.7/7 gaddr 10.0.0.250/0 laddr 10.0.0.250/0 type 8 code 0", "198.51.100.7")]
    public void Asa_icmp_connections_start_at_the_right_host(string message, string source) =>
        Assert.Equal(source, Parse("cisco-asa", Asa + message).ClientIp);

    [Fact]
    public void Asa_106023_and_106100_with_users_keep_ports_and_ignore_addresses_in_the_user_name()
    {
        var p = Parse("cisco-asa", Asa + "%ASA-4-106023: Deny tcp src outside:203.0.113.5/51234(LOCAL\\x dst inside:9.9.9.9/1) dst inside:10.0.0.5/22(LOCAL\\y) by access-group \"OUTSIDE_IN\" [0x0, 0x0]");
        Assert.Equal(("203.0.113.5", "10.0.0.5", "OUTSIDE_IN"), (p.ClientIp, p.DestinationIp!, p.RuleName!));
        Assert.Equal(51234, p.SourcePort);
        Assert.Equal(22, p.DestinationPort);
        p = Parse("cisco-asa", Asa + "%ASA-6-106100: access-list OUTSIDE_IN denied tcp outside/203.0.113.5(51234)(LOCAL\\u, 12:tag) -> inside/10.0.0.5(22)(LOCAL\\v) hit-cnt 1 first hit [0x1, 0x2]");
        Assert.Equal(("203.0.113.5", FirewallAction.Deny), (p.ClientIp, p.Action!.Value));
        Assert.Equal(22, p.DestinationPort);
    }

    [Theory]
    // https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-722001-to-776020.html (format: "adds", example: "add")
    [InlineData("adds")]
    [InlineData("add")]
    public void Asa_threat_detection_shun_is_read_in_both_documented_spellings(string word) =>
        Assert.Equal("203.0.113.9", Parse("cisco-asa", Asa + $"%ASA-4-733102: Threat-detection {word} host 203.0.113.9 to shun list").ClientIp);

    [Fact]
    public void Asa_logins()
    {
        // https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-602101-to-622102.html
        var p = Parse("cisco-asa", Asa + "%ASA-6-611101: User authentication succeeded: IP address: 203.0.113.9, Uname: admin");
        Assert.Equal((FirewallAction.Allow, "auth"), (p.Action!.Value, p.EventType!));
        Assert.Equal(ParseOutcome.Skipped, Outcome("cisco-asa", Asa + "%ASA-6-605004: Login denied from serial to console for user \"admin\"", out _));
        // https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-715001-to-721019.html
        p = Parse("cisco-asa", Asa + "%ASA-6-716038: Group <g> User <bob> IP <203.0.113.9> Authentication: successful, Session Type: WebVPN.");
        Assert.Equal((FirewallAction.Allow, "auth"), (p.Action!.Value, p.EventType!));
    }

    [Theory]
    [InlineData("%ASA-6-113015: AAA user authentication Rejected : reason = Invalid password : local database : user = x : user IP = 10.0.0.1 : user IP = 203.0.113.9")]
    [InlineData("%ASA-6-113005: AAA user authentication Rejected : reason = AAA failure : server = 10.1.1.1 : user = a : user IP = 10.0.0.1 b : user IP = 203.0.113.9")]
    [InlineData("%ASA-6-716039: Group <g> User <x> IP <10.0.0.1> IP <203.0.113.9> Authentication: rejected, Session Type: WebVPN.")]
    public void Asa_user_names_cannot_override_the_source(string message)
    {
        var p = Parse("cisco-asa", Asa + message);
        Assert.Equal(("203.0.113.9", FirewallAction.Deny), (p.ClientIp, p.Action!.Value));
    }

    [Theory]
    // https://www.cisco.com/c/ja_jp/td/docs/security/firepower/Syslogs/b_fptd_syslog_guide/security-event-syslog-messages.html
    [InlineData("Fastpath", FirewallAction.Allow)]
    [InlineData("Trust", FirewallAction.Allow)]
    [InlineData("Block", FirewallAction.Deny)]
    [InlineData("Block with reset", FirewallAction.Reject)]
    [InlineData("Interactive Block", FirewallAction.Deny)]
    [InlineData("Interactive Block with reset", FirewallAction.Reject)]
    [InlineData("Default Action", FirewallAction.Unknown)]
    public void Ftd_access_control_actions(string word, FirewallAction action)
    {
        foreach (var family in new[] { "FTD", "NGIPS" })
        {
            var p = Parse("cisco-asa", $"2026-11-21T10:00:00Z ftd01 %{family}-1-430003: EventPriority: Low, DeviceUUID: b2433c5c-a6a1-11eb, InstanceID: 2, FirstPacketSecond: 2026-11-21T10:00:00Z, ConnectionID: 4, AccessControlRuleAction: {word}, SrcIP: 203.0.113.5, DstIP: 10.0.0.5, SrcPort: 51234, DstPort: 22, Protocol: tcp, AccessControlRuleName: r, InitiatorBytes: 74, ResponderBytes: 6");
            Assert.Equal((action, "203.0.113.5"), (p.Action!.Value, p.ClientIp));
            Assert.Equal(22, p.DestinationPort);
        }
    }

    [Theory]
    [InlineData("Dropped", FirewallAction.Drop)]
    [InlineData("Would have dropped", FirewallAction.Alert)]
    public void Ftd_inline_results(string word, FirewallAction action) =>
        Assert.Equal(action, Parse("cisco-asa", $"2026-11-21T10:00:00Z ftd01 %FTD-1-430001: DeviceUUID: x, SrcIP: 203.0.113.5, DstIP: 10.0.0.5, SrcPort: 51234, DstPort: 80, Protocol: tcp, GID: 1, SID: 1000, Message: SQL injection, InlineResult: {word}").Action);

    // ------------------------------------------------------------------ Palo Alto
    // https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions

    private static string Pan(string type, params (int Index, string Value)[] fields)
    {
        var f = new string[60];
        Array.Fill(f, "");
        (f[0], f[1], f[2], f[3], f[6]) = ("1", "2026/11/21 10:00:00", "012345678901", type, "2026/11/21 10:00:00");
        foreach (var (i, v) in fields)
            f[i] = v;
        return "Nov 21 10:00:01 pa01 " + string.Join(',', f);
    }

    [Theory]
    [InlineData("random-drop", FirewallAction.Drop)]
    [InlineData("syncookie-sent", FirewallAction.Alert)]
    [InlineData("override-lockout", FirewallAction.Deny)]
    [InlineData("drop-all-packets", FirewallAction.Drop)]
    [InlineData("reset both", FirewallAction.Reject)]
    [InlineData("drop ICMP", FirewallAction.Drop)]
    [InlineData("sinkhole", FirewallAction.Deny)]
    [InlineData("block-ip", FirewallAction.Deny)]
    public void PanOs_documented_threat_actions(string word, FirewallAction action)
    {
        var p = Parse("paloalto", Pan("THREAT", (4, "flood"), (7, "203.0.113.5"), (8, "10.0.0.5"), (24, "1"), (25, "80"), (29, "tcp"), (30, word), (32, "TCP Flood(8501)"), (34, "high"), (35, "client-to-server")));
        Assert.Equal((action, "TCP Flood(8501)", "203.0.113.5"), (p.Action!.Value, p.ThreatName!, p.ClientIp));
    }

    [Fact]
    public void PanOs_globalprotect_and_auth_positions()
    {
        // globalprotect-log-fields: 8 event id, 12 user, 15 public IP, 28 status, 33 portal; authentication-log-fields: 8 source IP, 9 user, 20 event type
        var gp = Parse("paloalto", Pan("GLOBALPROTECT", (8, "gateway-auth"), (12, "bob"), (15, "203.0.113.9"), (17, "10.9.9.9"), (28, "failure"), (33, "GP-Portal")));
        Assert.Equal(("203.0.113.9", FirewallAction.Deny, "auth", "GP-Portal"), (gp.ClientIp, gp.Action!.Value, gp.EventType!, gp.RuleName!));
        var auth = Parse("paloalto", Pan("AUTH", (8, "203.0.113.9"), (9, "bob"), (12, "policy1"), (20, "auth-fail")));
        Assert.Equal(("203.0.113.9", FirewallAction.Deny), (auth.ClientIp, auth.Action!.Value));
    }

    [Fact]
    public void PanOs_system_login_failure_uses_the_last_from()
    {
        // system-log-fields: 8 event id, 14 description
        var p = Parse("paloalto", Pan("SYSTEM", (4, "auth"), (8, "auth-fail"), (14, "failed authentication for user 'x' From: 10.0.0.1.'. Reason: Invalid username/password. From: 203.0.113.9.")));
        Assert.Equal("203.0.113.9", p.ClientIp);
    }

    // ------------------------------------------------------------------ WatchGuard
    // https://www.watchguard.com/help/docs/fireware/12/en-US/log_catalog/Log-Catalog_v12_7.pdf

    private const string Wg = "Nov 21 10:00:00 firebox 80B20C0000000 firewall: ";

    [Theory]
    [InlineData("msg_id=\"1100-0004\" Authentication of firewall user [user1@Firebox-DB] from 203.0.113.9 was accepted", FirewallAction.Allow)]
    [InlineData("msg_id=\"1100-0005\" Authentication of Firewall user [test@RADIUS] from 203.0.113.9 was rejected, received an Access-Reject response from the RADIUS server", FirewallAction.Deny)]
    [InlineData("msg_id=\"3E00-0002\" Management user admin from 203.0.113.9 logged in", FirewallAction.Allow)]
    [InlineData("msg_id=\"3E00-0003\" Management user admin from 203.0.113.9 log in attempt was rejected.", FirewallAction.Deny)]
    // a user name cannot supply the address or the result
    [InlineData("msg_id=\"1100-0005\" Authentication of Firewall user [x] from 10.0.0.1 was accepted@RADIUS] from 203.0.113.9 was rejected, password is incorrect", FirewallAction.Deny)]
    [InlineData("msg_id=\"1100-0004\" Authentication of firewall user [rejected@Firebox-DB] from 203.0.113.9 was accepted", FirewallAction.Allow)]
    public void WatchGuard_logins(string message, FirewallAction action)
    {
        var p = Parse("watchguard", Wg + message);
        Assert.Equal(("203.0.113.9", action, "auth"), (p.ClientIp, p.Action!.Value, p.EventType!));
    }

    [Fact]
    public void WatchGuard_traffic_text_cannot_turn_a_packet_into_a_login()
    {
        var p = Parse("watchguard", Wg + "msg_id=\"3000-0149\" Deny 0-External 1-Trusted 40 tcp 20 127 203.0.113.9 10.0.1.2 53008 80 app_name=\"Authentication of a login \" msg=\"Application identified\" (HTTP-00)");
        Assert.Equal(("traffic", "HTTP-00"), (p.EventType!, p.RuleName!));
        Assert.Equal(80, p.DestinationPort);
    }

    [Theory]
    [InlineData("3000-0159", "PORT scan attack against 10.0.1.51 from 203.0.113.9 detected.", "10.0.1.51", FirewallAction.Alert)]
    [InlineData("3000-0158", "IP scan attack against 10.0.1.51 from 203.0.113.9 detected.", "10.0.1.51", FirewallAction.Alert)]
    [InlineData("3000-0153", "SYN flood attack against 10.0.1.51 from 203.0.113.9 detected. 500 SYN packets dropped since last alarm.", "10.0.1.51", FirewallAction.Drop)]
    [InlineData("3000-0152", "IPv4 source route attack from 203.0.113.9 detected.", null, FirewallAction.Alert)]
    [InlineData("3000-0161", "DDOS from client 203.0.113.9 detected.", null, FirewallAction.Alert)]
    [InlineData("3000-0169", "IP spoofing: Traffic detected from 203.0.113.9 to 10.0.1.51.", "10.0.1.51", FirewallAction.Alert)]
    public void WatchGuard_attack_alarms_are_threat_events(string id, string message, string? destination, FirewallAction action)
    {
        var p = Parse("watchguard", Wg + $"msg_id=\"{id}\" {message}");
        Assert.Equal(("203.0.113.9", action, "threat"), (p.ClientIp, p.Action!.Value, p.EventType!));
        Assert.Equal(destination, p.DestinationIp);
        Assert.NotNull(p.ThreatName);
    }

    [Fact]
    public void WatchGuard_ips_and_terminated_connections()
    {
        var ips = Parse("watchguard", Wg + "msg_id=\"3000-0150\" Deny 1-Trusted 0-External 1440 tcp 20 61 10.0.1.2 192.168.130.126 55810 80 offset 5 A 447868619 win 54 signature_name=\"EXPLOIT Apple QuickTime\" signature_cat=\"Misc\" signature_id=\"1112464\" severity=\"4\" sig_vers=\"18.124\" msg=\"IPS detected\" (HTTP-00)");
        Assert.Equal(("threat", "EXPLOIT Apple QuickTime"), (ips.EventType!, ips.ThreatName!));
        Assert.Equal(80, ips.DestinationPort);
        var end = Parse("watchguard", Wg + "msg_id=\"3000-0151\" Allow 1-Trusted 0-External tcp 10.0.1.2 220.181.90.24 53018 80 app_id=\"63\" app_cat_id=\"18\" app_ctl_disp=\"2\" duration=\"80\" sent_bytes=\"652\" rcvd_bytes=\"423\" (HTTP-00)");
        Assert.Equal((FirewallAction.Allow, "HTTP-00"), (end.Action!.Value, end.RuleName!));
        Assert.Equal(80, end.DestinationPort);
    }

    // ------------------------------------------------------------------ Juniper
    // Structured keys: https://github.com/elastic/integrations/tree/main/packages/juniper_srx (test-idp.log, test-ids.log, test-flow.log)

    [Fact]
    public void Juniper_structured_idp_and_screen_keys()
    {
        var idp = Parse("juniper-srx", "<165>1 2026-11-21T10:00:00Z srx RT_IDP - IDP_ATTACK_LOG_EVENT [junos@2636.1.1.1.2.129 epoch-time=\"1795255200\" message-type=\"SIG\" source-address=\"203.0.113.5\" source-port=\"12345\" destination-address=\"10.0.0.5\" destination-port=\"80\" protocol-name=\"TCP\" service-name=\"SERVICE_IDP\" application-name=\"HTTP\" rule-name=\"3\" rulebase-name=\"IPS\" policy-name=\"Recommended\" export-id=\"20175\" repeat-count=\"0\" action=\"DROP\" threat-severity=\"HIGH\" attack-name=\"HTTP:MISC:GENERIC-DIR-TRAVERSAL\" username=\"unknown-user\"]");
        Assert.Equal(("203.0.113.5", "10.0.0.5", FirewallAction.Drop, "HTTP:MISC:GENERIC-DIR-TRAVERSAL"), (idp.ClientIp, idp.DestinationIp!, idp.Action!.Value, idp.ThreatName!));
        Assert.Equal(80, idp.DestinationPort);
        var screen = Parse("juniper-srx", "<11>1 2026-11-21T10:00:00Z srx RT_IDS - RT_SCREEN_TCP [junos@2636.1.1.1.2.129 attack-name=\"TCP sweep!\" source-address=\"203.0.113.5\" source-port=\"6000\" destination-address=\"10.0.0.5\" destination-port=\"1433\" source-zone-name=\"untrust\" interface-name=\"fe-0/0/2.0\" action=\"drop\"]");
        Assert.Equal(("203.0.113.5", "TCP sweep", FirewallAction.Drop), (screen.ClientIp, screen.ThreatName!, screen.Action!.Value));
        Assert.Equal(1433, screen.DestinationPort);
    }

    [Fact]
    public void Juniper_session_limit_without_a_source_is_still_an_event()
    {
        var p = Parse("juniper-srx", "Nov 21 10:00:00 srx RT_IDS: RT_SCREEN_SESSION_LIMIT: Dst IP session limit! destination: 10.0.0.5, zone name: untrust, interface name: ge-0/0/0.0, action: drop");
        Assert.Equal(("-", "10.0.0.5"), (p.ClientIp, p.DestinationIp!));
    }

    [Fact]
    public void Juniper_quoted_values_cannot_contain_other_keys()
    {
        var p = Parse("juniper-srx", "<14>1 2026-11-21T10:00:00Z srx RT_FLOW - RT_FLOW_SESSION_DENY [junos@2636.1.1.1.2.129 username=\"x source-address=10.9.9.9 source-address=\\\"10.8.8.8\\\" \" source-address=\"203.0.113.5\" source-port=\"37233\" destination-address=\"10.0.0.5\" destination-port=\"22\" protocol-id=\"6\" policy-name=\"deny\" reason=\"Denied by policy\"]");
        Assert.Equal("203.0.113.5", p.ClientIp);
    }

    [Theory]
    [InlineData("Nov 21 10:00:00 srx sshd[1]: SSHD_LOGIN_FAILED: Login failed for user 'x' from host '10.0.0.1' from host '203.0.113.9'")]
    [InlineData("Nov 21 10:00:00 srx sshd[1]: SSHD_LOGIN_FAILED: Login failed for user 'RT_FLOW_SESSION_DENY session denied 10.0.0.1/1->10.0.0.2/2 0x0' from host '203.0.113.9'")]
    public void Juniper_login_user_cannot_fake_another_event(string line)
    {
        var p = Parse("juniper-srx", line);
        Assert.Equal(("203.0.113.9", "auth", FirewallAction.Deny), (p.ClientIp, p.EventType!, p.Action!.Value));
    }

    // ------------------------------------------------------------------ Meraki
    // https://documentation.meraki.com/General_Administration/Monitoring_and_Reporting/Syslog_Event_Types_and_Log_Samples
    // "1 all" / "0 all" and ip_flow_start are not on that page; "1 all" is in the Elastic cisco_meraki test data (test-flows.log).

    [Theory]
    [InlineData("flows src=192.168.1.186 dst=8.8.8.8 mac=58:1F:AA:CE:61:F2 protocol=udp sport=55719 dport=53 pattern: allow all", FirewallAction.Allow, 53)]
    [InlineData("firewall src=192.168.1.186 dst=8.8.8.8 mac=58:1F:AA:CE:61:F2 protocol=udp sport=55719 dport=53 pattern: deny all", FirewallAction.Deny, 53)]
    [InlineData("flows src=192.168.1.186 dst=8.8.8.8 protocol=udp sport=55719 dport=53 pattern: 1 all", FirewallAction.Allow, 53)]
    [InlineData("flows src=192.168.1.186 dst=8.8.8.8 protocol=udp sport=55719 dport=53 pattern: 0 all", FirewallAction.Deny, 53)]
    [InlineData("flows deny src=10.20.213.144 dst=192.168.111.5 mac=00:F4:B9:78:58:01 protocol=tcp sport=52421 dport=80", FirewallAction.Deny, 80)]
    [InlineData("l7_firewall src=10.10.10.3 dst=104.21.4.210 protocol=tcp sport=59526 dport=443 decision=blocked", FirewallAction.Deny, 443)]
    [InlineData("gp_firewall src=10.203.1.19 dst=23.111.186.186 vlan=1 protocol=udp sport=48915 dport=123 decision=allowed rule=2", FirewallAction.Allow, 123)]
    [InlineData("cellular_firewall src=10.10.10.11 dst=10.241.77.255 protocol=udp sport=9 dport=7 pattern: allow all", FirewallAction.Allow, 7)]
    [InlineData("vpn_firewall src=10.10.10.11 dst=10.241.77.255 protocol=udp sport=9 dport=7 pattern: deny (src 10.10.0.0/16)", FirewallAction.Deny, 7)]
    [InlineData("ip_flow_start src=10.10.10.11 dst=8.8.8.8 protocol=udp sport=9 dport=53 translated_src_ip=198.51.100.2 translated_port=9", FirewallAction.Allow, 53)]
    public void Meraki_flow_lines(string rest, FirewallAction action, int port)
    {
        var p = Parse("meraki", "1380664994.337961231 MX84 " + rest);
        Assert.Equal((action, "traffic"), (p.Action!.Value, p.EventType!));
        Assert.Equal(port, p.DestinationPort);
    }

    [Theory]
    [InlineData("type=anyconnect_vpn_auth_failure msg= 'Peer IP=203.0.113.9Peer port[8748] AAA[8]: AAA authenticate failed '", FirewallAction.Deny)]
    [InlineData("type=anyconnect_vpn_auth_failure msg= 'Peer IP=203.0.113.9 Peer port[8748] AAA[8]: AAA authenticate failed '", FirewallAction.Deny)]
    [InlineData("type=anyconnect_vpn_auth_failure msg= 'Peer IP=2001:db8::9 Peer port[8748] AAA[8]: AAA authenticate failed '", FirewallAction.Deny)]
    [InlineData("type=anyconnect_vpn_auth_success msg= 'Peer IP=203.0.113.9 Peer port=57096 AAA[7]: AAA authentication successful '", FirewallAction.Allow)]
    [InlineData("type=anyconnect_vpn_auth_failure remote_ip=203.0.113.9 user='a'", FirewallAction.Deny)]
    public void Meraki_anyconnect_logins(string rest, FirewallAction action)
    {
        var p = Parse("meraki", "1380664994.337961231 MX84 events " + rest);
        Assert.Equal(rest.Contains("2001:") ? "2001:db8::9" : "203.0.113.9", p.ClientIp);
        Assert.Equal((action, "auth"), (p.Action!.Value, p.EventType!));
    }

    // ------------------------------------------------------------------ SonicWall
    // SonicOS 6.5.4 Log Events Reference Guide, https://content.etilize.com/Additional-pdf8/1046911894.pdf

    private const string Sw = "Feb 26 22:47:37 10.8.139.192 id=firewall sn=18B16989BF80 time=\"2019-02-26 06:47:37\" fw=10.8.139.192 pri=6 c=1024 ";

    [Theory]
    [InlineData("m=597 msg=\"ICMP packet allowed\" n=1 src=203.0.113.5:8:X1 dst=10.0.0.5:1:X0 proto=icmp/8 fw_action=\"NA\"", FirewallAction.Allow, "traffic")]
    [InlineData("m=598 n=1 src=203.0.113.5:8:X1 dst=10.0.0.5:1:X0 proto=icmp/8 fw_action=\"NA\"", FirewallAction.Allow, "traffic")]
    [InlineData("m=602 n=1 src=203.0.113.5:8:X1 dst=10.0.0.5:53:X0 proto=udp/dns fw_action=\"NA\"", FirewallAction.Allow, "traffic")]
    [InlineData("m=1235 n=1 src=203.0.113.5:8:X1 dst=10.0.0.5:53:X0 proto=udp/dns fw_action=\"NA\"", FirewallAction.Allow, "traffic")]
    [InlineData("m=174 n=1 src=203.0.113.5:8:X1 dst=10.0.0.5:53:X0 proto=udp/dns fw_action=\"NA\"", FirewallAction.Drop, "traffic")]
    [InlineData("m=36 msg=\"TCP connection dropped\" n=1 src=203.0.113.5:8:X1 dst=10.0.0.5:53:X0 proto=tcp/dns fw_action=\"NA\"", FirewallAction.Drop, "traffic")]
    [InlineData("m=1154 msg=\"Application Control Detection Alert: x\" n=1 src=203.0.113.5:8:X1 dst=10.0.0.5:53:X0 fw_action=\"NA\"", FirewallAction.Alert, "threat")]
    [InlineData("m=82 msg=\"Possible port scan detected\" n=1 src=203.0.113.5:8:X1 dst=10.0.0.5:53:X0 fw_action=\"NA\"", FirewallAction.Alert, "threat")]
    [InlineData("m=177 msg=\"Probable TCP FIN scan detected\" n=1 src=203.0.113.5:8:X1 dst=10.0.0.5:53:X0 fw_action=\"NA\"", FirewallAction.Alert, "threat")]
    [InlineData("m=809 msg=\"Gateway Anti-Virus Alert: Injected.AZ (Trojan) blocked.\" n=1 src=203.0.113.5:80:X1 dst=10.0.0.5:53:X0 fw_action=\"NA\"", FirewallAction.Deny, "threat")]
    [InlineData("m=30 n=1 src=203.0.113.5:8:X1 dst=10.0.0.5:53:X0", FirewallAction.Deny, "auth")]
    [InlineData("m=33 n=1 src=203.0.113.5:8:X1 dst=10.0.0.5:53:X0", FirewallAction.Deny, "auth")]
    [InlineData("m=31 n=1 src=203.0.113.5:8:X1 dst=10.0.0.5:53:X0", FirewallAction.Allow, "auth")]
    [InlineData("m=14 msg=\"Web site access denied\" n=1 src=203.0.113.5:8:X1 dst=10.0.0.5:80:X0 fw_action=\"drop\"", FirewallAction.Drop, "traffic")]
    public void SonicWall_documented_message_ids(string rest, FirewallAction action, string type)
    {
        var p = Parse("sonicwall", Sw + rest);
        Assert.Equal((action, type, "203.0.113.5"), (p.Action!.Value, p.EventType!, p.ClientIp));
    }

    [Fact]
    public void SonicWall_arcsight_lines_are_read_as_cef()
    {
        var p = Parse("cef", "Feb 26 22:54:05 10.8.139.192 FEB 26 2019 06:54:05 18B16989BF80 CEF:0|SonicWall|NSa 3650|6.5.4.1-25n|1431|ICMPv6 Packets Received|4|cat=0 gcat=6 srcV6=2001:db8::1 deviceInboundInterface=X1 dstV6=2001:db8::2 proto=ipv6-icmp in=76 cnt=1559 fw_action=\"drop\"");
        Assert.Equal(("2001:db8::1", "2001:db8::2", FirewallAction.Drop), (p.ClientIp, p.DestinationIp!, p.Action!.Value));
    }

    // ------------------------------------------------------------------ FortiGate, Sophos, pfSense, Windows, AWS, Huawei, Zyxel, LEEF, JSON

    [Fact]
    public void FortiGate_ssl_vpn_login_failure_39426()
    {
        // https://docs.fortinet.com/document/fortigate/6.2.1/new-features/274515 (nanosecond eventtime);
        // https://community.fortinet.com/t5/FortiGate/Technical-Tip-Getting-alert-logs-frequently-on-FortiGate-for-SSL/ta-p/269153
        var p = Parse("fortigate", "date=2026-11-21 time=10:00:00 devname=\"fw\" devid=\"FGT60F\" eventtime=1747936050339390425 tz=\"+0200\" logid=\"0101039426\" type=\"event\" subtype=\"vpn\" level=\"alert\" vd=\"root\" logdesc=\"SSL VPN login fail\" action=\"ssl-login-fail\" tunneltype=\"ssl-web\" tunnelid=0 remip=203.0.113.9 user=\"a srcip=10.0.0.1 action=accept\" group=\"N/A\" dst_host=\"N/A\" reason=\"sslvpn_login_permission_denied\" msg=\"SSL user failed to logged in\"");
        Assert.Equal(("203.0.113.9", FirewallAction.Deny, "auth"), (p.ClientIp, p.Action!.Value, p.EventType!));
        Assert.Equal(new DateTimeOffset(2026, 11, 21, 10, 0, 0, TimeSpan.FromHours(2)), p.Timestamp);
    }

    [Theory]
    [InlineData("webfilter", "passthrough", "url", FirewallAction.Allow)]
    [InlineData("webfilter", "blocked", "url", FirewallAction.Deny)]
    [InlineData("app-ctrl", "pass", "traffic", FirewallAction.Allow)]
    [InlineData("ips", "detected", "threat", FirewallAction.Alert)]
    public void FortiGate_web_filter_and_allowed_application_logs_are_not_threats(string subtype, string action, string type, FirewallAction expected)
    {
        var p = Parse("fortigate", $"date=2026-11-21 time=10:00:00 devname=\"fw\" devid=\"FGT60F\" logid=\"0317013312\" type=\"utm\" subtype=\"{subtype}\" srcip=10.0.0.9 dstip=198.51.100.7 dstport=443 proto=6 action=\"{action}\" hostname=\"example.com\" catdesc=\"News\" app=\"HTTPS\" attack=\"x\"");
        Assert.Equal((type, expected), (p.EventType!, p.Action!.Value));
        Assert.Equal(type == "threat", p.ThreatName is not null);
    }

    [Fact]
    public void Sophos_documented_lines()
    {
        // https://docs.sophos.com/nsg/sophos-firewall/21.0/syslog/index.html
        var fw = Parse("sophos", "<30>device_name=\"SFW\" timestamp=\"2026-11-21T10:00:00+0100\" device_model=\"XGS\" device_serial_id=\"C0\" log_id=\"010101600001\" log_type=\"Firewall\" log_component=\"Invalid Traffic\" log_subtype=\"Denied\" log_version=1 severity=\"Information\" fw_rule_id=\"N/A\" message=\"Invalid packet.\" src_ip=\"203.0.113.5\" dst_ip=\"10.0.0.5\" protocol=\"TCP\" src_port=51234 dst_port=4444");
        Assert.Equal(FirewallAction.Deny, fw.Action);
        Assert.Equal(4444, fw.DestinationPort);
        Assert.Equal(new DateTimeOffset(2026, 11, 21, 10, 0, 0, TimeSpan.FromHours(1)), fw.Timestamp);
        var auth = Parse("sophos", "device=\"SFW\" date=2026-11-21 time=10:00:00 timezone=\"CET\" device_name=\"XG\" device_id=C0 log_id=062910617702 log_type=\"Event\" log_component=\"Firewall Authentication\" log_subtype=\"Authentication\" status=\"Failed\" priority=Notice user_name=\"x\" reason=\"wrong credentials\" src_ip=203.0.113.9 message=\"User x failed to login to Firewall through Local authentication mechanism\"");
        Assert.Equal((FirewallAction.Deny, "auth", "203.0.113.9"), (auth.Action!.Value, auth.EventType!, auth.ClientIp));
        var idp = Parse("sophos", "device=\"SFW\" date=2026-11-21 time=10:00:00 timezone=\"CET\" device_name=\"XG\" log_id=020703406001 log_type=\"IDP\" log_component=\"Signatures\" log_subtype=\"Drop\" priority=Warning signature_id=584 signature_msg=\"PROTOCOL-RPC portmap rusers request UDP\" src_ip=203.0.113.5 dst_ip=10.0.0.5 protocol=\"UDP\" src_port=1 dst_port=111");
        Assert.Equal((FirewallAction.Drop, "threat", "PROTOCOL-RPC portmap rusers request UDP"), (idp.Action!.Value, idp.EventType!, idp.ThreatName!));
    }

    [Fact]
    public void PfSense_unknown_action_is_skipped() =>
        // https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html : pass, block, unkn(%u)
        Assert.Equal(ParseOutcome.Skipped, Outcome("pfsense", "Nov 21 10:00:00 pf filterlog[1]: 5,,,1000000103,igb0,match,unkn(9),in,4,0x0,,64,0,0,none,17,udp,60,203.0.113.5,10.0.0.5,51234,53,40", out _));

    [Theory]
    // https://technet.microsoft.com/en-us/library/cc758040(WS.10).aspx (search extract): OPEN, OPEN-INBOUND, CLOSE, DROP, INFO-EVENTS-LOST
    [InlineData("OPEN", FirewallAction.Allow)]
    [InlineData("OPEN-INBOUND", FirewallAction.Allow)]
    [InlineData("CLOSE", FirewallAction.Allow)]
    [InlineData("DROP", FirewallAction.Drop)]
    public void Windows_firewall_actions(string word, FirewallAction action) =>
        Assert.Equal(action, Parse("windows-firewall", $"2026-11-21 10:00:00 {word} TCP 203.0.113.5 10.0.0.5 51234 3389 0 - 0 0 0 - - - RECEIVE").Action);

    [Fact]
    public void Aws_custom_formats_with_packet_addresses_and_many_fields()
    {
        // https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html (all versions together: more than 64 fields)
        var parser = LogFormatRegistry.Find("aws-vpc-flow")!.CreateParser(Ctx);
        var extra = string.Join(' ', Enumerable.Range(1, 70).Select(i => "eks-label-" + i));
        Assert.Equal(ParseOutcome.Skipped, parser.Parse("pkt-srcaddr pkt-dstaddr srcport dstport protocol start action log-status " + extra, out _));
        Assert.Equal(ParseOutcome.Parsed, parser.Parse("203.0.113.5 10.0.0.5 51234 22 6 1763719200 REJECT OK " + string.Join(' ', Enumerable.Repeat("-", 70)), out var p));
        Assert.Equal(("203.0.113.5", "10.0.0.5", FirewallAction.Reject), (p!.ClientIp, p.DestinationIp!, p.Action!.Value));
        Assert.Equal(22, p.DestinationPort);
    }

    [Fact]
    public void Huawei_session_log_with_a_space_separated_iso_header()
    {
        // https://groups.google.com/g/wazuh/c/TI6FLpXWquI (USG9560 sample)
        var p = Parse("huawei", "<190>2023-10-11 20:38:20 USG-01 %%01SECLOG/6/SESSION_TEARDOWN(l):IPVer=4,Protocol=udp,SourceIP=192.0.2.7,DestinationIP=198.51.100.7,SourcePort=59819,DestinationPort=53,SourceNatIP=198.51.100.1,SourceNatPort=18066,BeginTime=1697056661,EndTime=1697056700,SendPkts=1,SendBytes=70,RcvPkts=1,RcvBytes=538,SourceZone=trust,DestinationZone=untrust,PolicyName=Internet Acces,CloseReason=aged-out.");
        Assert.Equal(("192.0.2.7", "198.51.100.7", "Internet Acces", "USG-01"), (p.ClientIp, p.DestinationIp!, p.RuleName!, p.Device!));
        Assert.Equal(53, p.DestinationPort);
        Assert.Equal(608, p.ResponseSize);
    }

    [Fact]
    public void Zyxel_header_with_the_year_after_the_time()
    {
        // https://community.zyxel.com/en/discussion/20891/syslog-rfc3164-issue
        var p = Parse("zyxel", "<149>Jan 26 16:54:41 2024 usgflex100 src=\"203.0.113.5:51234\" dst=\"10.0.0.5:22\" msg=\"Match default rule, DROP\" note=\"ACCESS BLOCK\" user=\"unknown\" devID=\"bccf4fd0c8a7\" cat=\"Security Policy\"");
        Assert.Equal(new DateTimeOffset(2024, 1, 26, 16, 54, 41, TimeSpan.Zero), p.Timestamp);
        Assert.Equal("usgflex100", p.Device);
    }

    [Theory]
    // https://www.ibm.com/docs/en/dsm?topic=overview-leef-event-components : 0x or x followed by 1 to 4 hex digits
    [InlineData("^", '^')]
    [InlineData("x5E", '^')]
    [InlineData("0x7c", '|')]
    [InlineData("0x07C", '|')]
    [InlineData("x9", '\t')]
    public void Leef_delimiters(string spec, char delimiter)
    {
        var p = Parse("leef", $"Nov 21 10:00:00 host LEEF:2.0|Lancope|StealthWatch|1.0|41|{spec}|src=203.0.113.5{delimiter}dst=10.0.0.5{delimiter}dstPort=22{delimiter}proto=TCP{delimiter}action=Deny");
        Assert.Equal(("203.0.113.5", "10.0.0.5", FirewallAction.Deny), (p.ClientIp, p.DestinationIp!, p.Action!.Value));
        Assert.Equal(22, p.DestinationPort);
    }

    [Fact]
    public void Json_cloud_records()
    {
        // https://docs.cloud.google.com/firewall/docs/firewall-policy-rules-log-examples.md.txt
        var gcp = Parse("json", "{\"timestamp\":\"2026-11-21T10:00:00Z\",\"jsonPayload\":{\"connection\":{\"src_ip\":\"203.0.113.5\",\"src_port\":51234,\"dest_ip\":\"10.20.0.99\",\"dest_port\":80,\"protocol\":6},\"disposition\":\"DENIED\",\"rule_details\":{\"reference\":\"network:n/firewall:x\",\"action\":\"DENY\"}}}");
        Assert.Equal(("203.0.113.5", FirewallAction.Deny, "tcp"), (gcp.ClientIp, gcp.Action!.Value, gcp.Transport!));
        Assert.Equal(80, gcp.DestinationPort);
        // https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-logging-contents.html
        var aws = Parse("json", "{\"firewall_name\":\"f\",\"availability_zone\":\"us-east-1b\",\"event_timestamp\":\"1602627001\",\"event\":{\"timestamp\":\"2020-10-13T22:10:01.006481+0000\",\"event_type\":\"alert\",\"src_ip\":\"203.0.113.4\",\"src_port\":55555,\"dest_ip\":\"192.0.2.16\",\"dest_port\":111,\"proto\":\"TCP\",\"alert\":{\"action\":\"blocked\",\"signature\":\"test_tcp\",\"category\":\"\",\"severity\":1},\"verdict\":{\"action\":\"drop\"}}}");
        Assert.Equal(("203.0.113.4", FirewallAction.Deny, "test_tcp", "threat"), (aws.ClientIp, aws.Action!.Value, aws.ThreatName!, aws.EventType!));
        // https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azfwidpssignature
        var az = Parse("json", "{\"time\":\"2026-11-21T10:00:00Z\",\"category\":\"AZFWIdpsSignature\",\"properties\":{\"Protocol\":\"TCP\",\"SourceIp\":\"203.0.113.5\",\"SourcePort\":51234,\"DestinationIp\":\"10.0.0.5\",\"DestinationPort\":443,\"Action\":\"Alert\",\"SignatureId\":\"2032081\",\"Category\":\"MALWARE\",\"Description\":\"USER_AGENTS suspicious\",\"Severity\":2}}");
        Assert.Equal(("threat", "USER_AGENTS suspicious", FirewallAction.Alert), (az.EventType!, az.ThreatName!, az.Action!.Value));
    }

    // ------------------------------------------------------------------ log spoofing

    [Theory]
    // The real sshd source is the LAST "from <ip> port <n>" (the user name comes first and may hold anything).
    [InlineData("Failed password for invalid user root from 10.0.0.1 port 22 from 203.0.113.9 port 51234 ssh2")]
    [InlineData("Failed password for invalid user root from 10.0.0.1 port 22 ssh2 from 203.0.113.9 port 51234 ssh2")]
    [InlineData("Invalid user x from 10.0.0.1 port 1 from 203.0.113.9 port 51234")]
    [InlineData("Failed password for invalid user  from 203.0.113.9 port 51234 ssh2")]
    [InlineData("Invalid user  from 203.0.113.9 port 51234")]
    [InlineData("Failed password for invalid user a b c from 203.0.113.9 port 51234 ssh2")]
    [InlineData("Failed none for invalid user admin from 203.0.113.9 port 51234 ssh2")]
    [InlineData("Failed password for invalid user IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2 PROTO=TCP SPT=1 DPT=2 from 203.0.113.9 port 51234 ssh2")]
    [InlineData("Failed password for invalid user Accepted password for root from 203.0.113.9 port 51234 ssh2")]
    [InlineData("message repeated 5 times: [ Failed password for root from 203.0.113.9 port 51234 ssh2]")]
    public void Sshd_source_is_the_last_address(string message)
    {
        var p = Parse("netfilter", "Nov 21 10:00:00 gw01 sshd[2211]: " + message);
        Assert.Equal(("203.0.113.9", FirewallAction.Deny, "auth"), (p.ClientIp, p.Action!.Value, p.EventType!));
        Assert.Equal(51234, p.SourcePort);
    }

    [Fact]
    public void Sshd_repeat_count_stays_in_the_message()
    {
        var p = Parse("netfilter", "Nov 21 10:00:00 gw01 sshd[2211]: message repeated 5 times: [ Failed password for root from 203.0.113.9 port 4444 ssh2]");
        Assert.Equal("sshd: failed login for root (message repeated 5 times)", p.Url);
        Assert.Equal(4444, p.SourcePort);
    }

    public static TheoryData<string, string> EmbeddedRecords()
    {
        var d = new TheoryData<string, string>();
        (string Id, string Text)[] records =
        [
            ("cisco-asa", "%ASA-4-106023: Deny tcp src outside:10.0.0.1/1 dst inside:10.0.0.2/2 by access-group \"x\""),
            ("cef", "CEF:0|a|b|c|d|e|5|src=10.0.0.1 dst=10.0.0.2 act=deny"),
            ("leef", "LEEF:1.0|a|b|c|d|src=10.0.0.1\tdst=10.0.0.2\taction=deny"),
            ("huawei", "%%01POLICY/6/POLICYDENY(l): vsys=public, protocol=6, source-ip=10.0.0.1, destination-ip=10.0.0.2, time=2026/11/21 10:00:00"),
            ("fortigate", "date=2026-11-21 time=10:00:00 devid=FGT logid=1 type=traffic srcip=10.0.0.1 dstip=10.0.0.2 action=accept"),
            ("sophos", "device=SFW log_id=1 log_type=Firewall log_subtype=Allowed src_ip=10.0.0.1 dst_ip=10.0.0.2"),
            ("sonicwall", "id=firewall sn=1 m=36 src=10.0.0.1:1:X1 dst=10.0.0.2:2:X0"),
            ("stormshield", "id=firewall logtype=filter src=10.0.0.1 dst=10.0.0.2 action=block"),
            ("zyxel", "src=10.0.0.1:1 dst=10.0.0.2:2 devID=1 cat=firewall msg=DROP"),
            ("checkpoint", "action:\"Accept\"; origin:\"10.9.9.9\"; product:\"VPN-1\"; src:\"10.0.0.1\"; dst:\"10.0.0.2\""),
            ("watchguard", "msg_id=\"3000-0148\" Deny 0-External 1-Trusted 60 tcp 20 64 10.0.0.1 10.0.0.2 1 2 (x)"),
            ("pfsense", "filterlog: 5,,,1000000103,igb0,match,block,in,4,0x0,,64,0,0,none,17,udp,60,10.0.0.1,10.0.0.2,51234,53,40"),
            ("juniper-srx", "RT_FLOW_SESSION_DENY: session denied 10.0.0.1/1->10.0.0.2/2 0x0 junos-ssh 6(0) deny(global) untrust trust"),
            ("mikrotik", "firewall,info x input: in:ether1 out:x, proto TCP (SYN), 10.0.0.1:1->10.0.0.2:2, len 60"),
            ("keyvalue", "src=10.0.0.1 dst=10.0.0.2 action=accept proto=tcp dport=22 a=1 b=2 c=3 d=4 e=5 f=6 g=7"),
            ("netfilter", "IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2 LEN=60 PROTO=TCP SPT=1 DPT=2")
        ];
        foreach (var (id, text) in records)
            foreach (var header in new[]
                     {
                         "Nov 21 10:00:00 gw01 sshd[2211]: Failed password for invalid user {0} from 203.0.113.9 port 51234 ssh2",
                         "Nov 21 10:00:00 gw01 sshd[2211]: Invalid user {0} from 203.0.113.9 port 51234",
                         "<86>1 2026-11-21T10:00:00Z gw01 sshd 2211 - - Invalid user {0} from 203.0.113.9 port 51234",
                         "Nov 21 10:00:00 web01 nginx: 203.0.113.9 - - [21/Nov/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"{0}\""
                     })
                d.Add(id, header.Replace("{0}", text, StringComparison.Ordinal));
        return d;
    }

    [Theory]
    [MemberData(nameof(EmbeddedRecords))]
    public void A_firewall_record_inside_another_programs_message_is_not_an_event(string formatId, string line)
    {
        // netfilter reads sshd lines itself - then the real source must win
        var outcome = Outcome(formatId, line, out var p);
        Assert.True(outcome != ParseOutcome.Parsed || p!.ClientIp == "203.0.113.9", $"{formatId}: {p?.ClientIp}");
        // the same in a mixed file, whatever the main format is
        outcome = new MultiFormatParser(LogFormatRegistry.Find(formatId)!, Ctx).Parse(line, out p);
        Assert.True(outcome != ParseOutcome.Parsed || p!.ClientIp == "203.0.113.9", $"mixed: {p?.ClientIp}");
    }

    [Theory]
    [InlineData("fortigate", "date=2026-11-21 time=10:00:00 devname=\"fw\" devid=\"F\" logid=\"1\" type=\"traffic\" user=\"x srcip=10.0.0.1 action=accept\" srcip=203.0.113.9 dstip=10.0.0.5 action=\"deny\" srcip=10.0.0.2 action=\"accept\"")]
    [InlineData("fortigate", "date=2026-11-21 time=10:00:00 devname=\"fw\" devid=\"F\" logid=\"1\" type=\"traffic\" user=\"x\\\" srcip=10.0.0.1 action=accept \\\"\" srcip=203.0.113.9 dstip=10.0.0.5 action=\"deny\"")]
    [InlineData("fortigate", "date=2026-11-21 time=10:00:00 devname=fw devid=F logid=1 type=traffic user=' srcip=203.0.113.9 dstip=10.0.0.5 action=deny msg=hello")]
    [InlineData("sophos", "device_name=\"SFW\" timestamp=\"2026-11-21T10:00:00+0000\" log_id=\"1\" log_type=\"Firewall\" user_name=\"x src_ip=10.0.0.1 log_subtype=Allowed\" log_subtype=\"Denied\" src_ip=\"203.0.113.9\" dst_ip=\"10.0.0.5\" src_ip=\"10.0.0.2\"")]
    [InlineData("stormshield", "id=firewall time=\"2026-11-21 10:00:00\" fw=\"SN\" tz=+0000 startime=\"2026-11-21 10:00:00\" user=\"x src=10.0.0.1 action=pass\" src=203.0.113.9 dst=10.0.0.5 action=block logtype=\"filter\" src=10.0.0.2")]
    [InlineData("cef", "Nov 21 10:00:00 fw CEF:0|V|P|1|1|deny|5|act=deny suser=x src\\=10.0.0.1 act\\=allow src=203.0.113.9 dst=10.0.0.5 msg=src\\=10.0.0.2 src=10.0.0.3 act=allow")]
    [InlineData("leef", "Nov 21 10:00:00 fw LEEF:2.0|V|P|1|1|^|action=deny^usrName=x src=10.0.0.1 action=allow^src=203.0.113.9^dst=10.0.0.5^src=10.0.0.3^action=allow")]
    [InlineData("json", "{\"time\":\"2026-11-21T10:00:00Z\",\"http\":{\"request\":{\"headers\":{\"src_ip\":\"10.0.0.1\",\"action\":\"allow\"}}},\"event\":{\"src_ip\":\"203.0.113.9\",\"dest_ip\":\"10.0.0.5\",\"action\":\"deny\"}}")]
    [InlineData("json", "{\"time\":\"2026-11-21T10:00:00Z\",\"user\":\"\\\",\\\"src_ip\\\":\\\"10.0.0.1\",\"src_ip\":\"203.0.113.9\",\"dest_ip\":\"10.0.0.5\",\"action\":\"deny\",\"src_ip\":\"10.0.0.2\"}")]
    [InlineData("json", "{\"time\":\"2026-11-21T10:00:00Z\",\"ua\":\"\\ud800\",\"\\udfff\":1,\"src_ip\":\"203.0.113.9\",\"dest_ip\":\"10.0.0.5\",\"action\":\"deny\"}")]
    [InlineData("keyvalue", "2026-11-21T10:00:00Z fw01 user=\"x src=10.0.0.1 action=accept\" src=203.0.113.9 dst=10.0.0.5 action=deny src=10.0.0.2 action=accept")]
    [InlineData("checkpoint", "<134>1 2026-11-21T10:00:00Z GW CheckPoint 1 - [action:\"Deny\"; user:\"x\\\"; src:\\\"10.0.0.1\\\"; \"; origin:\"198.51.100.1\"; product:\"VPN-1 & FireWall-1\"; src:\"203.0.113.9\"; dst:\"10.0.0.5\"; action:\"Accept\"; src:\"10.0.0.2\"]")]
    public void Attacker_text_cannot_override_source_and_action(string formatId, string line)
    {
        var p = Parse(formatId, line);
        Assert.Equal("203.0.113.9", p.ClientIp);
        Assert.Equal(FirewallAction.Deny, p.Action);
    }

    [Theory]
    // commas in a value must not switch the reader to "k=v, k=v" mode; many words in a value are no reason to drop the event
    [InlineData("keyvalue", "2026-11-21T10:00:00Z fw01 src=203.0.113.9 dst=10.0.0.5 action=deny user=\"a, b, c, d, e, f, g, h, i\"")]
    [InlineData("keyvalue", "2026-11-21T10:00:00Z fw01 src=203.0.113.9 dst=10.0.0.5 action=deny msg=a, b, c, d, e, f, g, h, i")]
    [InlineData("keyvalue", "2026-11-21T10:00:00Z fw01 src=203.0.113.9 dst=10.0.0.5 action=deny url=\"/CEF:0|x LEEF:1.0| ] \\\" HTTP/1.1\"")]
    [InlineData("fortigate", "date=2026-11-21 time=10:00:00 devname=\"fw\" devid=\"F\" logid=\"1\" type=\"traffic\" srcip=203.0.113.9 dstip=10.0.0.5 action=\"deny\" url=\"/CEF:0|a|b|c|d|e|5|x\"")]
    [InlineData("zyxel", "Nov 21 10:00:00 usg src=\"203.0.113.9:51234\" dst=\"10.0.0.5:22\" msg=\"CEF:0, Match default rule, DENY\" note=\"ACCESS BLOCK\" devID=\"b\" cat=\"Security Policy\"")]
    public void Attacker_text_cannot_hide_an_event(string formatId, string line)
    {
        var p = Parse(formatId, line);
        Assert.Equal(("203.0.113.9", FirewallAction.Deny), (p.ClientIp, p.Action!.Value));
    }

    [Fact]
    public void Many_http_headers_cannot_push_the_addresses_out_of_a_json_event()
    {
        var headers = string.Join(',', Enumerable.Range(0, 260).Select(i => $"{{\"name\":\"x{i}\",\"value\":\"{i}\"}}"));
        var more = string.Join(',', Enumerable.Range(0, 260).Select(i => "\"src_ip\":\"10.0.0.1\""));
        var p = Parse("json", "{\"event_timestamp\":\"1602627001\",\"event\":{\"http\":{\"h\":[" + headers + "],\"m\":{" + more + "}},\"src_ip\":\"203.0.113.9\",\"dest_ip\":\"10.0.0.5\",\"dest_port\":443,\"proto\":\"TCP\",\"verdict\":{\"action\":\"drop\"}}}");
        Assert.Equal(("203.0.113.9", "10.0.0.5", FirewallAction.Drop), (p.ClientIp, p.DestinationIp!, p.Action!.Value));
    }

    [Fact]
    public void Asa_connection_numbers_of_two_firewalls_do_not_mix()
    {
        var parser = LogFormatRegistry.Find("cisco-asa")!.CreateParser(Ctx);
        Assert.Equal(ParseOutcome.Parsed, parser.Parse("Nov 21 2026 10:00:00 asa02 : %ASA-6-302013: Built outbound TCP connection 900 for outside:198.51.100.7/443 (198.51.100.7/443) to inside:10.9.9.9/50000 (10.9.9.9/50000)", out _));
        Assert.Equal(ParseOutcome.Parsed, parser.Parse(Asa + "%ASA-6-302014: Teardown TCP connection 900 for outside:203.0.113.5/51234 to inside:10.0.0.5/22 duration 0:00:05 bytes 1234 TCP FINs", out var p));
        Assert.Equal("203.0.113.5", p!.ClientIp);
    }

    [Theory]
    [InlineData("<166>Nov 21 10:00:00 10.1.1.1 Nov 21 2026 09:59:59 fw01 : ")]
    [InlineData("Nov 21 10:00:00 localhost CiscoASA[999]: ")]
    [InlineData("<166>Nov 21 2026 10:00:00: ")]
    [InlineData("<166>:Nov 21 10:00:00 UTC: ")]
    [InlineData("<166>1 2026-11-21T10:00:00Z fw01 - - - - ")]
    [InlineData("2026-11-21T10:00:00Z fw01 : ")]
    public void Asa_headers_stay_readable(string header) =>
        Assert.Equal("203.0.113.5", Parse("cisco-asa", header + "%ASA-4-106023: Deny tcp src outside:203.0.113.5/51234 dst inside:10.0.0.5/22 by access-group \"A\"").ClientIp);

    [Theory]
    [InlineData("system,error,critical login failure for user x from 10.0.0.1 via ssh from 203.0.113.9 via ssh")]
    [InlineData("system,error,critical login failure for user a: in:ether1 out:x, proto TCP (SYN), 10.0.0.1:1->10.0.0.2:2, len 60 from 203.0.113.9 via ssh")]
    public void MikroTik_login_source_is_the_last_address(string message)
    {
        // https://manual.mikrotik.com/docs/7.25/diagnostics-monitoring-and-troubleshooting/log/
        var p = Parse("mikrotik", "Nov 21 10:00:00 mt1 " + message);
        Assert.Equal(("203.0.113.9", "auth", FirewallAction.Deny), (p.ClientIp, p.EventType!, p.Action!.Value));
    }

    [Theory]
    [InlineData("not-an-ip")]
    [InlineData("<script>alert(1)</script>")]
    [InlineData("fe80::1%<script>")]
    [InlineData("1.2")]
    [InlineData("12345")]
    [InlineData("0x7f.0.0.1")]
    [InlineData("010.0.0.1")]
    [InlineData("1.2.3.4.5")]
    [InlineData("::ffff:1.2.3.4:80:X")]
    public void Addresses_that_are_not_ips_are_not_stored(string text)
    {
        var p = ParsedLine.Network(text, DateTimeOffset.UnixEpoch, FirewallAction.Deny, "m", destinationIp: text);
        Assert.True(p.ClientIp is "-" or "fe80::1", p.ClientIp);
        Assert.True(p.DestinationIp is null or "fe80::1", p.DestinationIp);
    }

    [Fact]
    public void Control_characters_in_log_text_become_spaces()
    {
        var p = ParsedLine.Network("203.0.113.5", DateTimeOffset.UnixEpoch, FirewallAction.Deny, "a\0b\r\nc\u001b[31m", ruleName: "r\nx", threatName: "t\0", device: "d\u0007", transport: "t\ncp", eventType: "au\0th");
        foreach (var s in new[] { p.Url, p.RuleName, p.ThreatName, p.Device, p.Transport, p.EventType })
            Assert.DoesNotContain(s!, char.IsControl);
    }

    // ------------------------------------------------------------------ time stamps

    [Theory]
    [InlineData("Feb 29 10:00:00", 2026, 2024)]
    [InlineData("Feb 29 10:00:00", 2028, 2028)]
    [InlineData("Feb 29 10:00:00", 2029, 2028)]
    [InlineData("Nov 25 10:00:00", 2026, 2026)]
    [InlineData("Dec 31 23:59:59", 2026, 2025)]
    public void Yearless_dates_get_a_valid_year(string text, int referenceYear, int expectedYear)
    {
        var ctx = new LogParseContext(new DateTimeOffset(referenceYear, 11, 25, 12, 0, 0, TimeSpan.Zero), TimeSpan.Zero);
        Assert.True(LogTime.TryParse(text, ctx, out var t));
        Assert.Equal(expectedYear, t.Year);
        Assert.Equal(int.Parse(text.AsSpan(4, 2), CultureInfo.InvariantCulture), t.Day);
    }

    [Theory]
    [InlineData("Feb 30 10:00:00")]
    [InlineData("0001-01-01 00:00:00")]
    [InlineData("0001-01-01T00:00:00+14:00")]
    [InlineData("9999-12-31 23:59:59")]
    [InlineData("9999-12-31T23:59:59-14:00")]
    [InlineData("2026-11-21T10:00:00+99:00")]
    [InlineData("2026-11-21T10:00:00+15:00")]
    [InlineData("2026-02-30 10:00:00")]
    [InlineData("99999999999999999")]
    [InlineData("10:00:00Z")]
    [InlineData("10:00:00 01-11-2026")]
    [InlineData("000000000")]
    [InlineData("١٧٦٣٧١٩٢٠٠")]
    public void Impossible_time_stamps_are_rejected_without_an_exception(string text)
    {
        foreach (var offset in new[] { -14, 0, 14 })
        {
            var ctx = new LogParseContext(Ctx.ReferenceTime, TimeSpan.FromHours(offset));
            Assert.False(LogTime.TryParse(text, ctx, out _));
            Assert.False(FirewallTime.TryParse(text, ctx, out _, "+1400"));
            Assert.False(JavaTime.TryParse(text, "yyyy-MM-dd HH:mm:ss", ctx, out _));
        }
    }

    [Theory]
    [InlineData("20261121100000")]
    [InlineData("1795255200")]
    [InlineData("1795255200000")]
    [InlineData("1795255200000000")]
    [InlineData("1795255200000000000")]
    [InlineData("2026-11-21T10:00:00Z")]
    [InlineData("2026-11-21T12:00:00+0200")]
    [InlineData("2026-11-21 12:00:00 EET")]
    public void Supported_time_stamps(string text)
    {
        Assert.True(FirewallTime.TryParse(text, Ctx, out var t));
        Assert.Equal(new DateTimeOffset(2026, 11, 21, 10, 0, 0, TimeSpan.Zero), t.ToUniversalTime());
    }

    [Fact]
    public void Cisco_summer_time_zone_words_are_applied()
    {
        var p = Parse("cisco-asa", "<166>Jul 10 2026 10:00:00 CEST: %ASA-4-106023: Deny tcp src outside:203.0.113.5/51234 dst inside:10.0.0.5/22 by access-group \"A\"");
        Assert.Equal(new DateTimeOffset(2026, 7, 10, 10, 0, 0, TimeSpan.FromHours(2)), p.Timestamp);
    }

    [Theory]
    [InlineData("<١٣٤>1 2026-11-21T10:00:00Z gw app - - - hello")]
    [InlineData("<١٣٤>Nov 21 10:00:00 gw app: hello")]
    public void Non_ascii_digits_in_the_priority_do_not_throw(string line) => Assert.Null(SyslogEnvelope.Parse(line, Ctx).Priority);
}
