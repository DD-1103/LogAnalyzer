using System.Diagnostics;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.Services.LogFormats;

namespace LogAnalyzer.Tests;

/// <summary>Shared helpers for the key=value / structured firewall format tests.</summary>
internal static class Fw
{
    public static readonly LogParseContext Context = new(new DateTimeOffset(2026, 11, 21, 12, 0, 0, TimeSpan.Zero), TimeSpan.Zero);

    public static (ParseOutcome Outcome, ParsedLine? Line) Parse(string formatId, string line)
    {
        var format = LogFormatRegistry.Find(formatId) ?? throw new InvalidOperationException("Unknown format " + formatId);
        var outcome = format.CreateParser(Context).Parse(line, out var parsed);
        return (outcome, parsed);
    }

    public static ParsedLine Parsed(string formatId, string line)
    {
        var (outcome, parsed) = Parse(formatId, line);
        Assert.Equal(ParseOutcome.Parsed, outcome);
        Assert.NotNull(parsed);
        return parsed!;
    }

    public static void Outcome(ParseOutcome expected, string formatId, string line) => Assert.Equal(expected, Parse(formatId, line).Outcome);

    public static DateTimeOffset At(int h, int m, int s, int offsetHours = 0) =>
        new DateTimeOffset(2026, 11, 21, h, m, s, TimeSpan.FromHours(offsetHours));

    /// <summary>Checks every normalised field, including the time zone offset (DateTimeOffset equality ignores it).</summary>
    public static void Event(ParsedLine p, DateTimeOffset time, FirewallAction action, string eventType, string? src, string? dst,
        int? srcPort, int? dstPort, string? transport, string? rule = null, string? threat = null, string? device = null)
    {
        Assert.Equal(time, p.Timestamp);
        Assert.Equal(time.Offset, p.Timestamp.Offset);
        Assert.Equal(action, p.Action);
        Assert.Equal(action == FirewallAction.Unknown ? "EVENT" : action.ToString().ToUpperInvariant(), p.Method);
        Assert.Equal(eventType, p.EventType);
        Assert.Equal(src ?? "-", p.ClientIp);
        Assert.Equal(dst, p.DestinationIp);
        Assert.Equal(srcPort, p.SourcePort);
        Assert.Equal(dstPort, p.DestinationPort);
        Assert.Equal(transport, p.Transport);
        Assert.Equal(rule, p.RuleName);
        Assert.Equal(threat, p.ThreatName);
        Assert.Equal(device, p.Device);
        Assert.Equal(0, p.StatusCode);
        Assert.False(string.IsNullOrWhiteSpace(p.Url));
    }

    public static string SamplesDirectory()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "samples", "firewall")))
            dir = dir.Parent;
        return dir is null ? throw new DirectoryNotFoundException("samples/firewall not found") : Path.Combine(dir.FullName, "samples");
    }

    public static string[] Sample(string name) =>
        File.ReadAllLines(Path.Combine(SamplesDirectory(), "firewall", name + ".log")).Where(l => l.Length > 0).ToArray();

    public const string Apache =
        "203.0.113.5 - - [21/Nov/2026:10:00:00 +0000] \"GET /index.php?src=1.2.3.4&dst=5.6.7.8&action=deny HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"";

    public const string FortiDeny =
        "date=2026-11-21 time=11:10:00 devname=\"fw01\" devid=\"FGT60FTK0000LAB1\" eventtime=1795255800000000000 tz=\"+0100\" " +
        "logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" vd=\"root\" srcip=203.0.113.50 srcport=40000 " +
        "srcintf=\"wan1\" dstip=10.0.0.5 dstport=22 dstintf=\"internal\" proto=6 action=\"deny\" policyid=0 policyname=\"Deny-All\" " +
        "service=\"SSH\" sentbyte=60 rcvdbyte=0";
}

public class KeyValueReaderTests
{
    private static KeyValueLine Read(string text, KvMode mode = KvMode.Spaces, char delimiter = '\t')
    {
        var kv = new KeyValueLine();
        KeyValueReader.Read(text, kv, mode, delimiter);
        return kv;
    }

    [Fact]
    public void Reads_plain_quoted_single_quoted_escaped_and_empty_values()
    {
        var kv = Read("a=1 b=\"two words\" c='three x' d=\"esc \\\"q\\\" \\\\ end\" e= f=\"\" g=last");
        Assert.Equal("1", kv.Get("a"));
        Assert.Equal("two words", kv.Get("b"));
        Assert.Equal("three x", kv.Get("c"));
        Assert.Equal("esc \"q\" \\ end", kv.Get("d"));
        Assert.True(kv.Has("e"));
        Assert.Null(kv.Get("e"));
        Assert.True(kv.Has("f"));
        Assert.Null(kv.Get("f"));
        Assert.Equal("last", kv.Get("g"));
        Assert.Equal(7, kv.Count);
        Assert.Equal(0, kv.BareTokens);
    }

    [Fact]
    public void Keys_are_case_insensitive_and_unquoted_backslashes_are_kept()
    {
        var kv = Read("User=DOMAIN\\jdoe Path=C:\\Temp\\x");
        Assert.Equal("DOMAIN\\jdoe", kv.Get("user"));
        Assert.Equal("C:\\Temp\\x", kv.Get("PATH"));
    }

    [Fact]
    public void Reads_check_point_structured_data()
    {
        var kv = Read("[action:\"Drop\"; src:\"203.0.113.5\"; rule_name:\"Clean up\"; originsicname:\"cn=cp,o=gw;x\"; s_port:\"51234\"]");
        Assert.Equal("Drop", kv.Get("action"));
        Assert.Equal("203.0.113.5", kv.Get("src"));
        Assert.Equal("Clean up", kv.Get("rule_name"));
        Assert.Equal("cn=cp,o=gw;x", kv.Get("originsicname"));
        Assert.Equal(51234, FirewallFields.Source(kv).Port);
    }

    [Fact]
    public void Reads_comma_separated_pairs_with_spaces_in_values()
    {
        var kv = Read("vsys=public, protocol=6, source-ip=203.0.113.5, time=2026/11/21 10:00:00, rule-name=deny all", KvMode.Comma);
        Assert.Equal("2026/11/21 10:00:00", kv.Get("time"));
        Assert.Equal("deny all", kv.Get("rule-name"));
        Assert.Equal("203.0.113.5", kv.Get(KvField.SourceIp));
        Assert.Equal("6", kv.Get(KvField.Protocol));

        var plain = Read("k=v, k2=v2; k3=v3");
        Assert.Equal("v", plain.Get("k"));
        Assert.Equal("v2", plain.Get("k2"));
        Assert.Equal("v3", plain.Get("k3"));
    }

    [Fact]
    public void Huawei_body_with_free_text_and_parentheses()
    {
        var kv = Read("An intrusion was detected. (SyslogId=1, VSys=\"public\", SrcIp=192.0.2.66, Reference=, Action=Block)", KvMode.Comma);
        Assert.Equal("public", kv.Get("VSys"));
        Assert.Equal("192.0.2.66", kv.Get("SrcIp"));
        Assert.Null(kv.Get("Reference"));
        Assert.Equal("Block", kv.Get("Action"));
        Assert.Equal(4, kv.BareTokens);
    }

    [Fact]
    public void Reads_cef_extension_values_until_the_next_key()
    {
        var kv = Read("msg=Port scan detected src=203.0.113.5 request=http://x/?a=b&c=d cs1Label=Rule Name cs1=a\\=b end=1", KvMode.UntilNextKey);
        Assert.Equal("Port scan detected", kv.Get("msg"));
        Assert.Equal("203.0.113.5", kv.Get("src"));
        Assert.Equal("http://x/?a=b&c=d", kv.Get("request"));
        Assert.Equal("Rule Name", kv.Get("cs1Label"));
        Assert.Equal("a=b", kv.Get("cs1"));
        Assert.Equal("1", kv.Get("end"));
    }

    [Fact]
    public void Reads_delimited_pairs()
    {
        var kv = Read("src=1.2.3.4^dst=5.6.7.8^msg=a b c^empty=", KvMode.Delimiter, '^');
        Assert.Equal("1.2.3.4", kv.Get("src"));
        Assert.Equal("5.6.7.8", kv.Get("dst"));
        Assert.Equal("a b c", kv.Get("msg"));
        Assert.Null(kv.Get("empty"));
    }

    [Fact]
    public void Free_text_is_counted_as_bare_tokens()
    {
        var kv = Read("the quick brown fox \"jumps over\" http://a.b/c?d=e");
        Assert.Equal(0, kv.Count);
        Assert.Equal(6, kv.BareTokens);
    }

    [Theory]
    [InlineData("srcip", KvField.SourceIp)]
    [InlineData("src_ip", KvField.SourceIp)]
    [InlineData("source-ip", KvField.SourceIp)]
    [InlineData("source.ip", KvField.SourceIp)]
    [InlineData("SourceAddress", KvField.SourceIp)]
    [InlineData("s_ip", KvField.SourceIp)]
    [InlineData("client_ip", KvField.SourceIp)]
    [InlineData("dst", KvField.DestinationIp)]
    [InlineData("destination-address", KvField.DestinationIp)]
    [InlineData("spt", KvField.SourcePort)]
    [InlineData("s_port", KvField.SourcePort)]
    [InlineData("dpt", KvField.DestinationPort)]
    [InlineData("destination-port", KvField.DestinationPort)]
    [InlineData("ipproto", KvField.Protocol)]
    [InlineData("fw_action", KvField.Action)]
    [InlineData("@timestamp", KvField.Timestamp)]
    [InlineData("policyname", KvField.Rule)]
    [InlineData("srcmac", KvField.None)]
    public void Aliases_resolve_after_normalisation(string key, KvField expected) =>
        Assert.Equal(expected, KvAliases.Resolve(key).Field);

    [Theory]
    [InlineData("203.0.113.5", "203.0.113.5", null, null)]
    [InlineData("203.0.113.5:51234", "203.0.113.5", 51234, null)]
    [InlineData("203.0.113.5:51234:X1", "203.0.113.5", 51234, "X1")]
    [InlineData("[2001:db8::5]:443", "2001:db8::5", 443, null)]
    [InlineData("2001:db8::5", "2001:db8::5", null, null)]
    [InlineData("2001:db8::5:443", "2001:db8::5:443", null, null)]
    [InlineData("fw.example:80", null, null, null)]
    [InlineData("1.2.3", null, null, null)]
    [InlineData("", null, null, null)]
    public void Splits_endpoints(string value, string? ip, int? port, string? iface)
    {
        var e = FirewallFields.SplitEndpoint(value);
        Assert.Equal(ip, e.Ip);
        Assert.Equal(port, e.Port);
        Assert.Equal(iface, e.Interface);
    }

    [Theory]
    [InlineData("6", "tcp")]
    [InlineData("17", "udp")]
    [InlineData("1", "icmp")]
    [InlineData("47", "gre")]
    [InlineData("50", "esp")]
    [InlineData("58", "ipv6-icmp")]
    [InlineData("TCP", "tcp")]
    [InlineData("tcp/ssh", "tcp")]
    [InlineData("tcp/ip", "tcp")]
    [InlineData("ICMPv6", "ipv6-icmp")]
    [InlineData("ssh", null)]
    [InlineData("999", null)]
    public void Maps_protocols(string value, string? expected) => Assert.Equal(expected, FirewallFields.Transport(value));

    [Theory]
    [InlineData("accept", FirewallAction.Allow)]
    [InlineData("Allowed", FirewallAction.Allow)]
    [InlineData("pass", FirewallAction.Allow)]
    [InlineData("server-rst", FirewallAction.Allow)]
    [InlineData("close", FirewallAction.Allow)]
    [InlineData("deny", FirewallAction.Deny)]
    [InlineData("BLOCKED", FirewallAction.Deny)]
    [InlineData("discard", FirewallAction.Deny)]
    [InlineData("drop", FirewallAction.Drop)]
    [InlineData("dropped", FirewallAction.Drop)]
    [InlineData("reset-both", FirewallAction.Reject)]
    [InlineData("reset both", FirewallAction.Reject)]
    [InlineData("rst", FirewallAction.Reject)]
    [InlineData("detected", FirewallAction.Alert)]
    [InlineData("monitor", FirewallAction.Alert)]
    [InlineData("perf-stats", FirewallAction.Unknown)]
    [InlineData("", FirewallAction.Unknown)]
    public void Maps_action_words(string word, FirewallAction expected) => Assert.Equal(expected, FirewallFields.Action(word));

    [Theory]
    [InlineData("1795255200", 0L)]
    [InlineData("1795255200123", 1_230_000L)]
    [InlineData("1795255200123456", 1_234_560L)]
    [InlineData("1795255200123456789", 1_234_567L)]
    [InlineData("1795255200.5", 5_000_000L)]
    public void Reads_epochs_of_any_precision(string value, long ticksAfter)
    {
        Assert.True(FirewallTime.TryEpoch(value, out var ts));
        Assert.Equal(Fw.At(10, 0, 0).AddTicks(ticksAfter), ts);
    }

    [Theory]
    [InlineData("2026-11-21 10:00:00 UTC", 10, 0)]
    [InlineData("2026-11-21 11:00:00 CET", 11, 1)]
    [InlineData("2026-11-21T11:00:00+0100", 11, 1)]
    [InlineData("2026-11-21T11:00:00.000000+0100", 11, 1)]
    [InlineData("Nov 21 2026 05:00:00 -0500", 5, -5)]
    public void Reads_zones_and_offsets(string value, int hour, int offset)
    {
        Assert.True(FirewallTime.TryParse(value, Fw.Context, out var ts));
        Assert.Equal(Fw.At(hour, 0, 0, offset), ts);
        Assert.Equal(TimeSpan.FromHours(offset), ts.Offset);
    }

    [Fact]
    public void Applies_a_separate_zone_field_to_local_times()
    {
        Assert.True(FirewallTime.TryParse("2026-11-21", "11:00:00", "+0100", Fw.Context, out var ts));
        Assert.Equal(Fw.At(11, 0, 0, 1), ts);
        Assert.Equal(TimeSpan.FromHours(1), ts.Offset);
    }
}

public class FortiGateFormatTests
{
    [Fact]
    public void Deny_uses_date_time_and_tz()
    {
        var p = Fw.Parsed("fortigate", Fw.FortiDeny);
        Fw.Event(p, Fw.At(11, 10, 0, 1), FirewallAction.Deny, "traffic", "203.0.113.50", "10.0.0.5", 40000, 22, "tcp", "Deny-All", null, "fw01");
        Assert.Equal(60, p.ResponseSize);
        Assert.Equal("deny tcp 203.0.113.50:40000 -> 10.0.0.5:22 (policy Deny-All)", p.Url);
    }

    [Fact]
    public void Allow_inside_syslog_without_tz_uses_the_default_offset()
    {
        const string line = "<189>Nov 21 10:00:00 fw01 date=2026-11-21 time=10:00:00 devname=\"fw01\" devid=\"FGT60FTK0000LAB1\" " +
                            "logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" srcip=10.0.0.21 srcport=50211 dstip=198.51.100.20 " +
                            "dstport=443 proto=6 action=\"close\" policyid=3 policyname=\"lan-to-wan\" sentbyte=1830 rcvdbyte=5120";
        var p = Fw.Parsed("fortigate", line);
        Fw.Event(p, Fw.At(10, 0, 0), FirewallAction.Allow, "traffic", "10.0.0.21", "198.51.100.20", 50211, 443, "tcp", "lan-to-wan", null, "fw01");
        Assert.Equal(6950, p.ResponseSize);
    }

    [Fact]
    public void Eventtime_in_nanoseconds_when_date_is_missing()
    {
        const string line = "logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" devid=\"FGT60FTK0000LAB1\" eventtime=1795255200123456789 " +
                            "srcip=10.0.0.22 srcport=50112 dstip=198.51.100.21 dstport=53 proto=17 action=\"accept\" policyid=3";
        var p = Fw.Parsed("fortigate", line);
        Fw.Event(p, Fw.At(10, 0, 0).AddTicks(1_234_567), FirewallAction.Allow, "traffic", "10.0.0.22", "198.51.100.21", 50112, 53, "udp", "3", null,
            "FGT60FTK0000LAB1");
    }

    [Fact]
    public void Ips_event_is_a_threat()
    {
        var p = Fw.Parsed("fortigate", Fw.Sample("fortigate").First(l => l.Contains("type=\"utm\"")));
        Fw.Event(p, Fw.At(11, 30, 0, 1), FirewallAction.Drop, "threat", "192.0.2.66", "10.0.0.5", 40112, 80, "tcp", "5",
            "SQL injection attempt", "fw01");
        Assert.Equal("web_server: SQL injection attempt", p.Url);
    }

    [Fact]
    public void Passthrough_threat_is_an_alert()
    {
        const string line = "date=2026-11-21 time=10:00:00 devname=\"fw01\" devid=\"FGT1\" logid=\"0419016384\" type=\"utm\" subtype=\"ips\" " +
                            "srcip=192.0.2.66 dstip=10.0.0.5 srcport=1 dstport=80 proto=6 action=\"detected\" policyid=5 attack=\"X.Y\"";
        Assert.Equal(FirewallAction.Alert, Fw.Parsed("fortigate", line).Action);
    }

    [Fact]
    public void Admin_login_failure_is_auth_deny()
    {
        var p = Fw.Parsed("fortigate", Fw.Sample("fortigate").First(l => l.Contains("Admin login failed")));
        Fw.Event(p, Fw.At(11, 40, 0, 1), FirewallAction.Deny, "auth", "192.0.2.99", "198.51.100.1", null, null, null, null, null, "fw01");
        Assert.Contains("login failed", p.Url);
    }

    [Fact]
    public void Ssl_vpn_login_failure_uses_remip()
    {
        var p = Fw.Parsed("fortigate", Fw.Sample("fortigate").First(l => l.Contains("ssl-login-fail")));
        Fw.Event(p, Fw.At(11, 40, 30, 1), FirewallAction.Deny, "auth", "192.0.2.99", null, null, null, null, null, null, "fw01");
    }

    [Fact]
    public void Gui_login_address_comes_from_ui_and_vpn_tunnel_up_is_vpn()
    {
        const string login = "date=2026-11-21 time=10:00:00 devname=\"fw01\" logid=\"0100032001\" type=\"event\" subtype=\"system\" " +
                             "logdesc=\"Admin login successful\" user=\"admin\" ui=\"GUI(203.0.113.9)\" action=\"login\" status=\"success\"";
        var p = Fw.Parsed("fortigate", login);
        Assert.Equal("203.0.113.9", p.ClientIp);
        Assert.Equal(FirewallAction.Allow, p.Action);
        Assert.Equal("auth", p.EventType);

        const string tunnel = "date=2026-11-21 time=10:00:00 devname=\"fw01\" logid=\"0101037138\" type=\"event\" subtype=\"vpn\" " +
                              "logdesc=\"IPsec connection status changed\" action=\"tunnel-up\" remip=198.51.100.7 locip=198.51.100.1 " +
                              "remport=500 locport=500";
        var t = Fw.Parsed("fortigate", tunnel);
        Fw.Event(t, Fw.At(10, 0, 0), FirewallAction.Allow, "vpn", "198.51.100.7", "198.51.100.1", 500, 500, null, null, null, "fw01");
    }

    [Fact]
    public void System_event_without_addresses_is_skipped() =>
        Fw.Outcome(ParseOutcome.Skipped, "fortigate", Fw.Sample("fortigate").First(l => l.Contains("perf-stats")));

    [Theory]
    [InlineData("hello world")]
    [InlineData(Fw.Apache)]
    [InlineData("type=traffic srcip=1.2.3.4 dstip=5.6.7.8")]
    [InlineData("<134>Nov 21 10:00:00 usg60 src=\"203.0.113.5:51234\" dst=\"10.0.0.5:22\" msg=\"x\" devID=\"abc\" cat=\"Security Policy\"")]
    public void Other_lines_fail(string line) => Fw.Outcome(ParseOutcome.Failed, "fortigate", line);

    [Fact]
    public void Line_without_any_time_fails() =>
        Fw.Outcome(ParseOutcome.Failed, "fortigate", "logid=\"0000000013\" type=\"traffic\" srcip=1.2.3.4 dstip=5.6.7.8 action=\"deny\"");

    [Fact]
    public void Parses_100k_lines_quickly()
    {
        var parser = new FortiGateFormat().CreateParser(Fw.Context);
        var sample = Fw.Sample("fortigate");
        var sw = Stopwatch.StartNew();
        var parsed = 0;
        for (var i = 0; i < 100_000; i++)
            if (parser.Parse(sample[i % sample.Length], out _) == ParseOutcome.Parsed)
                parsed++;
        sw.Stop();
        Assert.True(parsed > 90_000);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(15), $"100k FortiGate lines took {sw.Elapsed}");
    }
}

public class SophosFormatTests
{
    [Fact]
    public void Denied_with_timezone_word()
    {
        const string line = "device=\"SFW\" date=2026-11-21 time=11:10:00 timezone=\"CET\" device_name=\"XG330\" device_id=C01001LAB0001 " +
                            "log_id=010101600002 log_type=\"Firewall\" log_component=\"Firewall Rule\" log_subtype=\"Denied\" status=\"Deny\" " +
                            "priority=Information duration=0 fw_rule_id=0 fw_rule_name=\"Default drop\" user_name=\"\" src_ip=203.0.113.50 " +
                            "dst_ip=10.0.0.5 protocol=\"TCP\" src_port=40000 dst_port=22 sent_bytes=60 recv_bytes=0 tran_src_ip= con_id=0";
        var p = Fw.Parsed("sophos", line);
        Fw.Event(p, Fw.At(11, 10, 0, 1), FirewallAction.Deny, "traffic", "203.0.113.50", "10.0.0.5", 40000, 22, "tcp", "Default drop", null, "XG330");
        Assert.Equal(60, p.ResponseSize);
    }

    [Fact]
    public void Allowed_v19_format_with_iso_timestamp()
    {
        var p = Fw.Parsed("sophos", Fw.Sample("sophos")[0]);
        Fw.Event(p, Fw.At(10, 0, 0), FirewallAction.Allow, "traffic", "10.0.0.21", "198.51.100.20", 50211, 443, "tcp", "lan-to-wan", null, "SFW");
        Assert.Equal(1830 + 5120, p.ResponseSize);
    }

    [Fact]
    public void Idp_drop_is_a_threat()
    {
        var p = Fw.Parsed("sophos", Fw.Sample("sophos").First(l => l.Contains("log_type=\"IDP\"")));
        Fw.Event(p, Fw.At(10, 30, 0), FirewallAction.Drop, "threat", "192.0.2.66", "10.0.0.5", 40112, 80, "tcp", "5", "SQL injection attempt", "XG330");
    }

    [Fact]
    public void Admin_login_failure_is_auth_deny()
    {
        var p = Fw.Parsed("sophos", Fw.Sample("sophos").First(l => l.Contains("log_component=\"Admin\"")));
        Fw.Event(p, Fw.At(10, 40, 0), FirewallAction.Deny, "auth", "192.0.2.99", null, null, null, null, null, null, "XG330");
        Assert.Contains("failed to login", p.Url);
    }

    [Fact]
    public void System_health_is_skipped_and_other_vendors_fail()
    {
        Fw.Outcome(ParseOutcome.Skipped, "sophos", Fw.Sample("sophos").First(l => l.Contains("System Health")));
        Fw.Outcome(ParseOutcome.Failed, "sophos", Fw.FortiDeny);
        Fw.Outcome(ParseOutcome.Failed, "sophos", Fw.Apache);
    }
}

public class SonicWallFormatTests
{
    [Fact]
    public void Dropped_packet_splits_ip_port_interface()
    {
        var p = Fw.Parsed("sonicwall", Fw.Sample("sonicwall").First(l => l.Contains("m=36")));
        Fw.Event(p, Fw.At(10, 10, 0), FirewallAction.Drop, "traffic", "203.0.113.50", "10.0.0.5", 40000, 20, "tcp", null, null, "0017C5LAB001");
        Assert.Equal("TCP packet dropped", p.Url);
    }

    [Fact]
    public void Closed_connection_is_allow_with_bytes_and_rule()
    {
        var p = Fw.Parsed("sonicwall", Fw.Sample("sonicwall")[0]);
        Fw.Event(p, Fw.At(10, 0, 0), FirewallAction.Allow, "traffic", "10.0.0.21", "198.51.100.20", 50211, 443, "tcp", "3 (LAN->WAN)", null,
            "0017C5LAB001");
        Assert.Equal(6950, p.ResponseSize);
    }

    [Fact]
    public void Ips_detection_is_alert_and_prevention_is_drop()
    {
        var lines = Fw.Sample("sonicwall").Where(l => l.Contains("IPS ")).ToArray();
        var detection = Fw.Parsed("sonicwall", lines.First(l => l.Contains("m=82")));
        Fw.Event(detection, detection.Timestamp, FirewallAction.Alert, "threat", "192.0.2.66", "10.0.0.5", detection.SourcePort, 80, "tcp", null,
            detection.ThreatName, "0017C5LAB001");
        Assert.StartsWith("WEB-ATTACKS ", detection.ThreatName);
        var prevention = Fw.Parsed("sonicwall", lines.First(l => l.Contains("m=83")));
        Assert.Equal(FirewallAction.Drop, prevention.Action);
        Assert.Equal("threat", prevention.EventType);
    }

    [Fact]
    public void Administrator_login_denied_is_auth()
    {
        var p = Fw.Parsed("sonicwall", Fw.Sample("sonicwall").First(l => l.Contains("m=30 ")));
        Fw.Event(p, Fw.At(10, 40, 0), FirewallAction.Deny, "auth", "192.0.2.99", "198.51.100.1", 51544, 443, null, null, null, "0017C5LAB001");
    }

    [Fact]
    public void Syslog_host_wins_over_serial_and_system_lines_are_skipped()
    {
        var p = Fw.Parsed("sonicwall", "<134>Nov 21 10:00:00 sw-lab " + Fw.Sample("sonicwall")[0]);
        Assert.Equal("sw-lab", p.Device);
        Fw.Outcome(ParseOutcome.Skipped, "sonicwall", Fw.Sample("sonicwall").First(l => l.Contains("m=1 ")));
    }

    [Fact]
    public void Other_vendors_fail()
    {
        Fw.Outcome(ParseOutcome.Failed, "sonicwall", Fw.Sample("stormshield")[0]);
        Fw.Outcome(ParseOutcome.Failed, "sonicwall", Fw.FortiDeny);
    }
}

public class CheckPointFormatTests
{
    [Fact]
    public void Log_exporter_drop_in_structured_data()
    {
        var p = Fw.Parsed("checkpoint", Fw.Sample("checkpoint").First(l => l.Contains("action:\"Drop\"")));
        Fw.Event(p, Fw.At(10, 10, 0), FirewallAction.Drop, "traffic", "203.0.113.50", "10.0.0.5", 40000, 20, "tcp", "Cleanup rule", null, "gw01");
    }

    [Fact]
    public void Plain_key_value_export()
    {
        var p = Fw.Parsed("checkpoint", Fw.Sample("checkpoint")[1]);
        Fw.Event(p, Fw.At(10, 0, 37), FirewallAction.Allow, "traffic", "10.0.0.22", "198.51.100.21", 50112, 53, "udp", "lan-to-wan", null,
            "198.51.100.1");
    }

    [Fact]
    public void Structured_data_as_the_whole_line()
    {
        const string line = "[action:\"Reject\"; origin:\"198.51.100.1\"; product:\"VPN-1 & FireWall-1\"; src:\"2001:db8::5\"; " +
                            "dst:\"2001:db8:1::10\"; proto:\"17\"; s_port:\"5353\"; service:\"53\"; rule:\"4\"; time:\"1795255200\"]";
        var p = Fw.Parsed("checkpoint", line);
        Fw.Event(p, Fw.At(10, 0, 0), FirewallAction.Reject, "traffic", "2001:db8::5", "2001:db8:1::10", 5353, 53, "udp", "4", null, "198.51.100.1");
    }

    [Fact]
    public void Ips_and_anti_bot_are_threats()
    {
        var ips = Fw.Parsed("checkpoint", Fw.Sample("checkpoint").First(l => l.Contains("product:\"IPS\"")));
        Fw.Event(ips, Fw.At(10, 30, 0), FirewallAction.Deny, "threat", "192.0.2.66", "10.0.0.5", 40112, 80, "tcp", "wan-to-dmz",
            "SQL injection attempt", "gw01");
        var bot = Fw.Parsed("checkpoint", Fw.Sample("checkpoint").First(l => l.Contains("Anti-Bot")));
        Fw.Event(bot, Fw.At(10, 50, 0), FirewallAction.Deny, "threat", "10.0.0.23", "198.51.100.200", 49152, 4444, "tcp", null,
            "Backdoor.Generic.C2", "gw01");
    }

    [Fact]
    public void Mobile_access_failed_login_is_auth_deny()
    {
        var p = Fw.Parsed("checkpoint", Fw.Sample("checkpoint").First(l => l.Contains("Failed Log In")));
        Fw.Event(p, Fw.At(10, 40, 0), FirewallAction.Deny, "auth", "192.0.2.99", "198.51.100.1", null, null, null, null, null, "gw01");
    }

    [Fact]
    public void Policy_install_is_skipped_and_others_fail()
    {
        Fw.Outcome(ParseOutcome.Skipped, "checkpoint", Fw.Sample("checkpoint").First(l => l.Contains("Policy installed")));
        Fw.Outcome(ParseOutcome.Failed, "checkpoint", Fw.FortiDeny);
        Fw.Outcome(ParseOutcome.Failed, "checkpoint", "the product of origin is unknown");
    }
}

public class HuaweiFormatTests
{
    [Fact]
    public void Policy_deny()
    {
        var p = Fw.Parsed("huawei", Fw.Sample("huawei").First(l => l.Contains("POLICYDENY")));
        Fw.Event(p, Fw.At(10, 10, 0), FirewallAction.Deny, "traffic", "203.0.113.50", "10.0.0.5", 40000, 20, "tcp", "default", null, "usg-lab");
    }

    [Fact]
    public void Policy_permit_and_session_teardown_are_allow()
    {
        var permit = Fw.Parsed("huawei", Fw.Sample("huawei").First(l => l.Contains("POLICYPERMIT")));
        Assert.Equal(FirewallAction.Allow, permit.Action);
        Assert.Equal("traffic", permit.EventType);

        var session = Fw.Parsed("huawei", Fw.Sample("huawei")[0]);
        Fw.Event(session, Fw.At(10, 0, 0), FirewallAction.Allow, "traffic", "10.0.0.21", "198.51.100.20", 50211, 443, "tcp", "lan-to-wan", null,
            "usg-lab");
        Assert.Equal(6950, session.ResponseSize);
    }

    [Fact]
    public void Ips_detect_is_a_threat()
    {
        var p = Fw.Parsed("huawei", Fw.Sample("huawei").First(l => l.Contains("%%01IPS")));
        Fw.Event(p, Fw.At(10, 30, 0), FirewallAction.Deny, "threat", "192.0.2.66", "10.0.0.5", 40112, 80, "tcp", "wan-to-dmz",
            "SQL injection attempt", "usg-lab");
    }

    [Fact]
    public void Ssh_login_failure_is_auth()
    {
        var p = Fw.Parsed("huawei", Fw.Sample("huawei").First(l => l.Contains("LOGIN_FAIL")));
        Fw.Event(p, Fw.At(10, 40, 0), FirewallAction.Deny, "auth", "192.0.2.99", null, null, null, null, null, null, "usg-lab");
    }

    [Fact]
    public void Cpu_message_is_skipped_and_others_fail()
    {
        Fw.Outcome(ParseOutcome.Skipped, "huawei", Fw.Sample("huawei").First(l => l.Contains("CPU_USAGE")));
        Fw.Outcome(ParseOutcome.Failed, "huawei", "<166>Nov 21 2026 10:00:00 asa : %ASA-4-106023: Deny tcp src outside:203.0.113.5/1 dst inside:10.0.0.5/22");
        Fw.Outcome(ParseOutcome.Failed, "huawei", "100%% sure");
        Fw.Outcome(ParseOutcome.Failed, "huawei", Fw.FortiDeny);
    }
}

public class MerakiFormatTests
{
    [Fact]
    public void Flows_deny_pattern()
    {
        var p = Fw.Parsed("meraki", Fw.Sample("meraki").First(l => l.Contains("pattern: deny all")));
        Fw.Event(p, Fw.At(10, 10, 0).AddTicks(1_234_967), FirewallAction.Deny, "traffic", "203.0.113.50", "10.0.0.5", 40000, 20, "tcp",
            "deny all", null, "mx-lab");
    }

    [Fact]
    public void Firewall_allow_pattern()
    {
        var p = Fw.Parsed("meraki", Fw.Sample("meraki")[0]);
        Assert.Equal(FirewallAction.Allow, p.Action);
        Assert.Equal("allow all", p.RuleName);
        Assert.Equal("198.51.100.20", p.DestinationIp);
        Assert.Equal(443, p.DestinationPort);
    }

    [Fact]
    public void Ids_alert_and_blocked_security_event()
    {
        var lines = Fw.Sample("meraki");
        var ids = Fw.Parsed("meraki", lines.First(l => l.Contains(" ids-alerts ")));
        Fw.Event(ids, ids.Timestamp, FirewallAction.Alert, "threat", "192.0.2.66", "10.0.0.5", ids.SourcePort, 80, "tcp", ids.RuleName,
            ids.ThreatName, "mx-lab");
        Assert.StartsWith("ET WEB_SERVER ", ids.ThreatName);
        Assert.StartsWith("1:", ids.RuleName);
        var blocked = Fw.Parsed("meraki", lines.First(l => l.Contains("ids_alerted")));
        Assert.Equal(FirewallAction.Deny, blocked.Action);
        Assert.Equal("threat", blocked.EventType);
    }

    [Fact]
    public void Vpn_auth_failure_and_collector_header()
    {
        var line = Fw.Sample("meraki").First(l => l.Contains("auth_failure"));
        var p = Fw.Parsed("meraki", line);
        Fw.Event(p, p.Timestamp, FirewallAction.Deny, "auth", "192.0.2.99", null, null, null, null, null, null, "mx-lab");

        var wrapped = Fw.Parsed("meraki", "Nov 21 10:00:00 192.0.2.10 " + Fw.Sample("meraki")[0][5..]);
        Assert.Equal("mx-lab", wrapped.Device);
    }

    [Fact]
    public void Vpn_status_is_skipped_and_others_fail()
    {
        Fw.Outcome(ParseOutcome.Skipped, "meraki", Fw.Sample("meraki").First(l => l.Contains("vpn_connectivity_change")));
        Fw.Outcome(ParseOutcome.Failed, "meraki", Fw.Apache);
        Fw.Outcome(ParseOutcome.Failed, "meraki", "1795255200 host unknown_type src=1.2.3.4");
        Fw.Outcome(ParseOutcome.Failed, "meraki", Fw.FortiDeny);
    }
}

public class StormshieldFormatTests
{
    [Fact]
    public void Filter_block_with_tz()
    {
        const string line = "id=firewall time=\"2026-11-21 11:10:00\" fw=\"fw01\" tz=+0100 startime=\"2026-11-21 11:10:00\" pri=5 confid=01 " +
                            "slotlevel=2 ruleid=9 srcif=\"Ethernet0\" srcifname=\"out\" ipproto=tcp dstif=\"Ethernet1\" dstifname=\"in\" proto=ssh " +
                            "src=203.0.113.50 srcport=40000 srcportname=ephemeral_fw_tcp dst=10.0.0.5 dstport=22 dstportname=ssh action=block logtype=\"filter\"";
        var p = Fw.Parsed("stormshield", line);
        Fw.Event(p, Fw.At(11, 10, 0, 1), FirewallAction.Deny, "traffic", "203.0.113.50", "10.0.0.5", 40000, 22, "tcp", "9", null, "fw01");
    }

    [Fact]
    public void Pass_is_allow_with_bytes()
    {
        var p = Fw.Parsed("stormshield", Fw.Sample("stormshield")[0]);
        Fw.Event(p, Fw.At(10, 0, 0), FirewallAction.Allow, "traffic", "10.0.0.21", "198.51.100.20", 50211, 443, "tcp", "3", null, "fw01");
        Assert.Equal(6950, p.ResponseSize);
    }

    [Fact]
    public void Alarm_is_a_threat()
    {
        var p = Fw.Parsed("stormshield", Fw.Sample("stormshield").First(l => l.Contains("logtype=\"alarm\"")));
        Fw.Event(p, Fw.At(10, 30, 0), FirewallAction.Deny, "threat", "192.0.2.66", "10.0.0.5", 40112, 80, "tcp", "5", "SQL injection attempt", "fw01");
    }

    [Fact]
    public void Auth_error_is_auth_deny()
    {
        var p = Fw.Parsed("stormshield", Fw.Sample("stormshield").First(l => l.Contains("logtype=\"auth\"")));
        Fw.Event(p, Fw.At(10, 40, 0), FirewallAction.Deny, "auth", "192.0.2.99", "198.51.100.1", 51544, 443, null, null, null, "fw01");
    }

    [Fact]
    public void System_is_skipped_and_others_fail()
    {
        Fw.Outcome(ParseOutcome.Skipped, "stormshield", Fw.Sample("stormshield").First(l => l.Contains("logtype=\"system\"")));
        Fw.Outcome(ParseOutcome.Failed, "stormshield", Fw.Sample("sonicwall")[0]);
        Fw.Outcome(ParseOutcome.Failed, "stormshield", Fw.FortiDeny);
    }
}

public class ZyxelFormatTests
{
    [Fact]
    public void Default_rule_drop_uses_syslog_time()
    {
        var p = Fw.Parsed("zyxel", Fw.Sample("zyxel").First(l => l.Contains("Match default rule")));
        Fw.Event(p, Fw.At(10, 10, 0), FirewallAction.Drop, "traffic", "203.0.113.50", "10.0.0.5", 40000, 20, "tcp", "default", null, "usg-lab");
    }

    [Fact]
    public void Accept_with_priority_rule()
    {
        var p = Fw.Parsed("zyxel", Fw.Sample("zyxel")[0]);
        Fw.Event(p, Fw.At(10, 0, 0), FirewallAction.Allow, "traffic", "10.0.0.21", "198.51.100.20", 50211, 443, "tcp", "priority 3", null, "usg-lab");
    }

    [Fact]
    public void Idp_is_a_threat()
    {
        var p = Fw.Parsed("zyxel", Fw.Sample("zyxel").First(l => l.Contains("cat=\"IDP\"")));
        Fw.Event(p, Fw.At(10, 30, 0), FirewallAction.Drop, "threat", "192.0.2.66", "10.0.0.5", 40112, 80, "tcp", null,
            "1000123 WEB-ATTACKS SQL injection attempt", "usg-lab");
    }

    [Fact]
    public void Failed_login_is_auth_deny()
    {
        var p = Fw.Parsed("zyxel", Fw.Sample("zyxel").First(l => l.Contains("Failed login")));
        Fw.Event(p, Fw.At(10, 40, 0), FirewallAction.Deny, "auth", "192.0.2.99", "198.51.100.1", 51544, 443, "tcp", null, null, "usg-lab");
    }

    [Fact]
    public void System_monitor_is_skipped_and_others_fail()
    {
        Fw.Outcome(ParseOutcome.Skipped, "zyxel", Fw.Sample("zyxel").First(l => l.Contains("System Monitor")));
        Fw.Outcome(ParseOutcome.Failed, "zyxel", Fw.FortiDeny);
        Fw.Outcome(ParseOutcome.Failed, "zyxel", Fw.Apache);
    }
}

public class CefFormatTests
{
    [Fact]
    public void Deny_with_rule_label_and_text_time()
    {
        var p = Fw.Parsed("cef", Fw.Sample("cef").First(l => l.Contains("traffic:deny")));
        Fw.Event(p, Fw.At(10, 10, 0), FirewallAction.Deny, "traffic", "203.0.113.50", "10.0.0.5", 40000, 20, "tcp", "Deny-All", null, "fw01");
        Assert.Equal("Connection denied", p.Url);
        Assert.Equal(60, p.ResponseSize);
    }

    [Fact]
    public void Allow_with_epoch_millisecond_time()
    {
        var line = Fw.Sample("cef").First(l => l.Contains("traffic:end") && l.Contains("spt=50211"));
        var p = Fw.Parsed("cef", line);
        Fw.Event(p, Fw.At(10, 0, 0), FirewallAction.Allow, "traffic", "10.0.0.21", "198.51.100.20", 50211, 443, "tcp", "lan-to-wan", null, "fw01");
        Assert.Equal(6950, p.ResponseSize);
    }

    [Fact]
    public void Ips_event_uses_threat_label()
    {
        var p = Fw.Parsed("cef", Fw.Sample("cef").First(l => l.Contains("|ips:")));
        Fw.Event(p, Fw.At(10, 30, 0), FirewallAction.Deny, "threat", "192.0.2.66", "10.0.0.5", 40112, 80, "tcp", "wan-to-dmz",
            "SQL injection attempt", "fw01");
        Assert.Equal("SQL injection attempt: Inbound request matched an IPS signature", p.Url);
    }

    [Fact]
    public void Authentication_failure()
    {
        var p = Fw.Parsed("cef", Fw.Sample("cef").First(l => l.Contains("auth:fail")));
        Fw.Event(p, Fw.At(10, 40, 0), FirewallAction.Deny, "auth", "192.0.2.99", "198.51.100.1", 51544, 443, "tcp", null, null, "fw01");
    }

    [Fact]
    public void Escapes_and_envelope_time_without_rt()
    {
        const string line = "<134>Nov 21 10:05:00 fw02 CEF:0|Example\\|Sec|EdgeFW|1|100|Port scan|7|src=203.0.113.50 dst=10.0.0.5 " +
                            "act=drop cat=/Attack/Scan msg=a\\=b c";
        var p = Fw.Parsed("cef", line);
        Fw.Event(p, Fw.At(10, 5, 0), FirewallAction.Drop, "threat", "203.0.113.50", "10.0.0.5", null, null, null, null, "Port scan", "fw02");
        Assert.Equal("Port scan: a=b c", p.Url);
    }

    [Fact]
    public void Without_any_time_fails_without_addresses_is_skipped_and_others_fail()
    {
        Fw.Outcome(ParseOutcome.Failed, "cef", "CEF:0|V|P|1|100|Deny|5|src=203.0.113.50 dst=10.0.0.5 act=deny");
        Fw.Outcome(ParseOutcome.Skipped, "cef", Fw.Sample("cef").First(l => l.Contains("system:cpu")));
        Fw.Outcome(ParseOutcome.Failed, "cef", "CEF:0|broken header");
        Fw.Outcome(ParseOutcome.Failed, "cef", Fw.Sample("leef")[0]);
        Fw.Outcome(ParseOutcome.Failed, "cef", Fw.FortiDeny);
    }
}

public class LeefFormatTests
{
    [Fact]
    public void Leef1_with_tabs_and_dev_time_format()
    {
        var p = Fw.Parsed("leef", Fw.Sample("leef").First(l => l.Contains("LEEF:1.0") && l.Contains("|deny|")));
        Fw.Event(p, Fw.At(10, 10, 0), FirewallAction.Deny, "traffic", "203.0.113.50", "10.0.0.5", 40000, 20, "tcp", "Deny-All", null, "fw01");
    }

    [Fact]
    public void Leef2_with_caret_delimiter()
    {
        var p = Fw.Parsed("leef", Fw.Sample("leef").First(l => l.Contains("LEEF:2.0") && l.Contains("|allow|")));
        Assert.Equal(FirewallAction.Allow, p.Action);
        Assert.Equal("traffic", p.EventType);
        Assert.Equal("lan-to-wan", p.RuleName);
        Assert.NotNull(p.ResponseSize);
    }

    [Fact]
    public void Leef2_hex_delimiter_and_java_time_with_zone()
    {
        const string line = "LEEF:2.0|V|P|1|deny|x5E|devTime=2026-11-21T11:00:00.000+0100^devTimeFormat=yyyy-MM-dd'T'HH:mm:ss.SSSZ^" +
                            "src=203.0.113.50^srcPort=40000^dst=10.0.0.5^dstPort=22^proto=6^action=drop^ruleName=r1";
        var p = Fw.Parsed("leef", line);
        Fw.Event(p, Fw.At(11, 0, 0, 1), FirewallAction.Drop, "traffic", "203.0.113.50", "10.0.0.5", 40000, 22, "tcp", "r1", null, null);
    }

    [Fact]
    public void Leef1_with_spaces_instead_of_tabs()
    {
        const string line = "<134>Nov 21 10:00:00 fw01 LEEF:1.0|V|P|1|deny|src=203.0.113.50 dst=10.0.0.5 dstPort=22 proto=TCP action=deny " +
                            "msg=Blocked by policy";
        var p = Fw.Parsed("leef", line);
        Fw.Event(p, Fw.At(10, 0, 0), FirewallAction.Deny, "traffic", "203.0.113.50", "10.0.0.5", null, 22, "tcp", null, null, "fw01");
        Assert.Equal("deny: Blocked by policy", p.Url);
    }

    [Fact]
    public void Threat_and_auth()
    {
        var threat = Fw.Parsed("leef", Fw.Sample("leef").First(l => l.Contains("ips-alert")));
        Assert.Equal("threat", threat.EventType);
        Assert.Equal(FirewallAction.Deny, threat.Action);
        Assert.Equal("SQL injection attempt", threat.ThreatName);
        var auth = Fw.Parsed("leef", Fw.Sample("leef").First(l => l.Contains("login-failed")));
        Assert.Equal("auth", auth.EventType);
        Assert.Equal(FirewallAction.Deny, auth.Action);
        Assert.Equal("192.0.2.99", auth.ClientIp);
    }

    [Fact]
    public void System_is_skipped_and_others_fail()
    {
        Fw.Outcome(ParseOutcome.Skipped, "leef", Fw.Sample("leef").First(l => l.Contains("|system|")));
        Fw.Outcome(ParseOutcome.Failed, "leef", Fw.Sample("cef")[0]);
        Fw.Outcome(ParseOutcome.Failed, "leef", "LEEF:1.0|only|three");
    }
}

public class JsonFirewallFormatTests
{
    [Fact]
    public void Ecs_deny()
    {
        var p = Fw.Parsed("json", Fw.Sample("json").First(l => l.Contains("\"denied\"")));
        Fw.Event(p, p.Timestamp, FirewallAction.Deny, "traffic", "203.0.113.50", "10.0.0.5", p.SourcePort, p.DestinationPort, "tcp",
            "deny-inbound", null, "fw01");
        Assert.Equal(TimeSpan.Zero, p.Timestamp.Offset);
    }

    [Fact]
    public void Ecs_allow_with_bytes()
    {
        var p = Fw.Parsed("json", Fw.Sample("json")[0]);
        Fw.Event(p, Fw.At(10, 0, 0), FirewallAction.Allow, "traffic", "10.0.0.21", "198.51.100.20", 50211, 443, "tcp", "lan-to-wan", null, "fw01");
        Assert.Equal(6950, p.ResponseSize);
    }

    [Fact]
    public void Aws_network_firewall_alert_and_netflow()
    {
        var alert = Fw.Parsed("json", Fw.Sample("json").First(l => l.Contains("\"alert\"")));
        Fw.Event(alert, Fw.At(10, 30, 0), FirewallAction.Deny, "threat", "192.0.2.66", "10.0.0.5", 40112, 80, "tcp", null,
            "SQL injection attempt", "fw01");
        var flow = Fw.Parsed("json", Fw.Sample("json").First(l => l.Contains("\"netflow\"")));
        Fw.Event(flow, Fw.At(10, 20, 0), FirewallAction.Allow, "traffic", "203.0.113.77", "10.0.0.10", 50000, 22, "tcp", null, null, "fw01");
    }

    [Fact]
    public void Azure_resource_specific_and_legacy_message()
    {
        var specific = Fw.Parsed("json", Fw.Sample("json").First(l => l.Contains("AZFWNetworkRule")));
        Assert.Equal(FirewallAction.Deny, specific.Action);
        Assert.Equal("deny-all", specific.RuleName);
        Assert.Equal("203.0.113.50", specific.ClientIp);

        const string legacy = "{\"time\":\"2026-11-21T10:10:06.0000000Z\",\"category\":\"AzureFirewallNetworkRule\",\"properties\":{\"msg\":" +
                              "\"TCP request from 203.0.113.50:51241 to 10.0.0.5:53. Action: Deny. Rule Collection: inbound. Rule: deny-all\"}}";
        var p = Fw.Parsed("json", legacy);
        Fw.Event(p, Fw.At(10, 10, 6), FirewallAction.Deny, "traffic", "203.0.113.50", "10.0.0.5", 51241, 53, "tcp", "deny-all", null, null);

        const string ids = "{\"time\":\"2026-11-21T10:30:00Z\",\"category\":\"AzureFirewallNetworkRule\",\"properties\":{\"msg\":" +
                           "\"TCP request from 192.0.2.66:40112 to 10.0.0.5:80. Action: Alert. Signature: 2008983. IDS: WEB_SERVER SQL Injection. " +
                           "Priority: 1. Classification: Web Application Attack\"}}";
        var t = Fw.Parsed("json", ids);
        Assert.Equal("threat", t.EventType);
        Assert.Equal(FirewallAction.Alert, t.Action);
        Assert.Equal("WEB_SERVER SQL Injection", t.ThreatName);
    }

    [Fact]
    public void Gcp_firewall_rule_log()
    {
        var p = Fw.Parsed("json", Fw.Sample("json").First(l => l.Contains("jsonPayload")));
        Fw.Event(p, p.Timestamp, FirewallAction.Allow, "traffic", "203.0.113.77", "10.0.0.10", p.SourcePort, 22, "tcp",
            "network:lab-vpc/firewall:allow-ssh", null, null);
    }

    [Fact]
    public void Opnsense_json()
    {
        var p = Fw.Parsed("json", Fw.Sample("json").First(l => l.Contains("__timestamp__")));
        Fw.Event(p, Fw.At(10, 50, 0), FirewallAction.Allow, "traffic", "10.0.0.23", "198.51.100.200", 49152, 4444, "tcp", "LAN allow all", null, null);
    }

    [Fact]
    public void Ecs_authentication_failure()
    {
        var p = Fw.Parsed("json", Fw.Sample("json").First(l => l.Contains("authentication")));
        Fw.Event(p, Fw.At(10, 40, 0), FirewallAction.Deny, "auth", "192.0.2.99", null, 51544, null, null, null, null, "fw01");
    }

    [Theory]
    [InlineData("{\"time\":\"2026-11-21T10:00:00Z\",\"remote_addr\":\"203.0.113.5\",\"request\":\"GET / HTTP/1.1\",\"status\":200}")]
    [InlineData("{\"timestamp\":\"2026-11-21T10:00:00Z\",\"client_ip\":\"203.0.113.5\",\"path\":\"/login\"}")]
    [InlineData("{\"source\":{\"ip\":\"203.0.113.5\"},\"destination\":{\"ip\":\"10.0.0.5\"}}")]
    [InlineData("{\"source\":{\"ip\":\"203.0.113.5\"")]
    [InlineData("[1,2,3]")]
    [InlineData("not json")]
    [InlineData(Fw.Apache)]
    public void Non_firewall_json_and_garbage_fail(string line) => Fw.Outcome(ParseOutcome.Failed, "json", line);

    [Fact]
    public void Deep_nesting_fails()
    {
        var deep = new string('[', 40) + new string(']', 40);
        Fw.Outcome(ParseOutcome.Failed, "json", "{\"a\":" + deep + "}");
    }

    [Fact]
    public void Json_inside_syslog_uses_envelope_time_and_host()
    {
        const string line = "<134>Nov 21 10:00:00 fw09 nfw: {\"src_ip\":\"203.0.113.50\",\"dest_ip\":\"10.0.0.5\",\"dest_port\":22,\"action\":\"drop\"}";
        var p = Fw.Parsed("json", line);
        Fw.Event(p, Fw.At(10, 0, 0), FirewallAction.Drop, "traffic", "203.0.113.50", "10.0.0.5", null, 22, null, null, null, "fw09");
    }
}

public class GenericKeyValueFormatTests
{
    [Fact]
    public void Unknown_vendor_drop()
    {
        var p = Fw.Parsed("keyvalue", Fw.Sample("generic-kv").First(l => l.Contains("action=drop")));
        Fw.Event(p, Fw.At(10, 10, 0), FirewallAction.Drop, "traffic", "203.0.113.50", "10.0.0.5", 40000, 20, "tcp", "deny-inbound", null, "gw-branch");
    }

    [Fact]
    public void Unknown_vendor_threat_and_auth()
    {
        var threat = Fw.Parsed("keyvalue", Fw.Sample("generic-kv").First(l => l.Contains("signature=")));
        Fw.Event(threat, Fw.At(10, 30, 0), FirewallAction.Deny, "threat", "192.0.2.66", "10.0.0.5", 40112, 80, "tcp", "wan-to-dmz",
            "SQL injection attempt", "gw-branch");
        var auth = Fw.Parsed("keyvalue", Fw.Sample("generic-kv").First(l => l.Contains("login_failed")));
        Fw.Event(auth, Fw.At(10, 40, 0), FirewallAction.Deny, "auth", "192.0.2.99", "198.51.100.1", null, 443, null, null, null, "gw-branch");
    }

    [Fact]
    public void Comma_separated_unknown_vendor()
    {
        const string line = "date=2026-11-21, time=10:00:00, src=203.0.113.50, dst=10.0.0.5, dport=22, proto=tcp, action=deny, policy=block all";
        var p = Fw.Parsed("keyvalue", line);
        Fw.Event(p, Fw.At(10, 0, 0), FirewallAction.Deny, "traffic", "203.0.113.50", "10.0.0.5", null, 22, "tcp", "block all", null, null);
    }

    [Theory]
    [InlineData(Fw.Apache)]
    [InlineData("the quick brown fox jumped src=1.2.3.4 over the lazy dog at=10:00 x=y")]
    [InlineData("<134>Nov 21 10:00:00 h app: src=203.0.113.5 user=x level=3")]
    [InlineData("src=203.0.113.5 dst=10.0.0.5 action=deny")]
    [InlineData("CEF:0|V|P|1|1|n|1|rt=1795255200000 src=203.0.113.5 dst=10.0.0.5 act=deny")]
    public void Rejects_non_firewall_lines(string line) => Fw.Outcome(ParseOutcome.Failed, "keyvalue", line);
}

public class FirewallFormatDetectionTests
{
    public static TheoryData<string, string> Samples => new()
    {
        { "fortigate", "fortigate" }, { "sophos", "sophos" }, { "sonicwall", "sonicwall" }, { "checkpoint", "checkpoint" },
        { "huawei", "huawei" }, { "meraki", "meraki" }, { "stormshield", "stormshield" }, { "zyxel", "zyxel" }, { "cef", "cef" },
        { "leef", "leef" }, { "json", "json" }, { "generic-kv", "keyvalue" }
    };

    [Theory]
    [MemberData(nameof(Samples))]
    public void Detector_picks_the_vendor_format(string file, string expectedId)
    {
        var lines = Fw.Sample(file);
        var detection = LogFormatDetector.Detect(lines.Take(LogFormatDetector.SampleLines).ToList(), Fw.Context);
        Assert.Equal(expectedId, detection.Format?.Id);
        Assert.Equal(1.0, detection.Ratio);
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void Every_sample_line_is_parsed_or_skipped_and_tells_the_story(string file, string formatId)
    {
        var parser = LogFormatRegistry.Find(formatId)!.CreateParser(Fw.Context);
        var events = new List<ParsedLine>();
        foreach (var line in Fw.Sample(file))
        {
            var outcome = parser.Parse(line, out var p);
            Assert.True(outcome != ParseOutcome.Failed, $"{file}: {line}");
            if (outcome == ParseOutcome.Parsed)
                events.Add(p!);
        }
        Assert.InRange(events.Count, 30, 80);
        // port scan: one source, 20+ destination ports within a minute
        var scan = events.Where(e => e.ClientIp == "203.0.113.50").ToList();
        Assert.True(scan.Select(e => e.DestinationPort).Distinct().Count() >= 20);
        Assert.True(scan.Max(e => e.Timestamp) - scan.Min(e => e.Timestamp) <= TimeSpan.FromMinutes(1));
        // brute force: 20+ connections to SSH within 5 minutes
        var brute = events.Where(e => e.ClientIp == "203.0.113.77" && e.DestinationPort == 22).ToList();
        Assert.True(brute.Count >= 20);
        Assert.True(brute.Max(e => e.Timestamp) - brute.Min(e => e.Timestamp) <= TimeSpan.FromMinutes(5));
        Assert.True(events.Count(e => e.EventType == "threat") >= 3);
        Assert.True(events.Count(e => e.EventType == "auth" && e.Action == FirewallAction.Deny) >= 3);
        Assert.Contains(events, e => e.DestinationPort == 4444 && e.ClientIp == "10.0.0.23");
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void Generic_reader_never_beats_a_vendor_format(string file, string formatId)
    {
        if (formatId == "keyvalue")
            return;
        var lines = Fw.Sample(file);
        int Count(string id)
        {
            var parser = LogFormatRegistry.Find(id)!.CreateParser(Fw.Context);
            return lines.Count(l => parser.Parse(l, out _) == ParseOutcome.Parsed);
        }
        Assert.True(Count("keyvalue") <= Count(formatId));
    }

    [Fact]
    public void Vendor_parsers_reject_other_vendors_lines()
    {
        var formats = Samples.Select(row => ((string)row[0], (string)row[1])).ToList();
        foreach (var (file, owner) in formats)
        {
            var line = Fw.Sample(file).First(l => Fw.Parse(owner, l).Outcome == ParseOutcome.Parsed);
            foreach (var (_, other) in formats)
            {
                if (other == owner || other == "keyvalue" || owner == "keyvalue")
                    continue;
                Assert.True(Fw.Parse(other, line).Outcome == ParseOutcome.Failed, $"{other} accepted a {owner} line: {line}");
            }
        }
    }

    [Fact]
    public void No_firewall_format_reads_the_apache_sample_and_combined_is_detected()
    {
        var lines = File.ReadLines(Path.Combine(Fw.SamplesDirectory(), "sample-access.log")).Where(l => l.Length > 0).ToList();
        foreach (var format in LogFormatRegistry.OfSource(LogSource.Firewall))
        {
            var parser = format.CreateParser(Fw.Context);
            var parsed = lines.Count(l => parser.Parse(l, out _) == ParseOutcome.Parsed);
            Assert.True(parsed == 0, $"{format.Id} parsed {parsed} Apache lines");
        }
        Assert.Equal(WebAccessLogFormat.FormatId, LogFormatDetector.Detect(lines.Take(LogFormatDetector.SampleLines).ToList(), Fw.Context).Format?.Id);
    }

    [Fact]
    public void All_formats_are_registered_with_their_specificity()
    {
        var expected = new Dictionary<string, int>
        {
            ["fortigate"] = 100, ["sophos"] = 100, ["sonicwall"] = 100, ["checkpoint"] = 100, ["huawei"] = 100, ["meraki"] = 100,
            ["stormshield"] = 100, ["zyxel"] = 100, ["cef"] = 50, ["leef"] = 50, ["json"] = 50, ["keyvalue"] = 10
        };
        foreach (var (id, specificity) in expected)
        {
            var format = LogFormatRegistry.Find(id);
            Assert.NotNull(format);
            Assert.Equal(specificity, format!.Specificity);
            Assert.Equal(LogSource.Firewall, format.Source);
        }
    }
}
