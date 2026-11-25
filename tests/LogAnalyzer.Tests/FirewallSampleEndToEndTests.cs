using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.Services.LogFormats;

namespace LogAnalyzer.Tests;

/// <summary>
/// Every file in samples/firewall, end to end and without a database: the format detector of the upload, the real
/// line parser (with its fallbacks), the events in timestamp order through the real <see cref="DetectionCore"/> with the
/// real default firewall rules. Samples are discovered on disk: a new sample fails here until it is added to
/// <see cref="Expectations"/>, and the expected table says exactly which rules fire and why a rule cannot.
/// </summary>
public class FirewallSampleEndToEndTests
{
    private const string PortScan = "Port scan";
    private const string Sweep = "Network sweep";
    private const string BruteForce = "Brute force on remote-access services";
    private const string Flood = "Flood of blocked connections";
    private const string Intrusion = "Intrusion prevention / threat event";
    private const string C2 = "Connection to backdoor / C2 port";
    private const string FailedLogins = "Repeated failed logins on the firewall / VPN";

    /// <summary>Every sample must trigger these, whatever the vendor: they only need connection logs.</summary>
    private static readonly string[] Mandatory = [PortScan, BruteForce, C2];

    /// <summary>The full story of a firewall that logs traffic, IPS events and logins.</summary>
    private static readonly string[] FullStory = [PortScan, BruteForce, Intrusion, C2, FailedLogins];

    /// <param name="Format">Format id the detector must choose.</param>
    /// <param name="Rules">Exactly the rules that fire.</param>
    /// <param name="Without">Rules of the full story that cannot fire, with the reason (empty = none).</param>
    private sealed record Expected(string Format, string[] Rules, params (string Rule, string Reason)[] Without);

    private static readonly Dictionary<string, Expected> Expectations = new(StringComparer.Ordinal)
    {
        ["aws-vpc-flow.log"] = new("aws-vpc-flow", [PortScan, Sweep, BruteForce, C2],
            (Intrusion, "a VPC flow record has addresses, ports, counters and ACCEPT / REJECT, no threat field"),
            (FailedLogins, "a VPC flow record describes a network flow, AWS writes no login events into it")),
        ["cef.log"] = new("cef", FullStory),
        ["checkpoint.log"] = new("checkpoint", FullStory),
        ["cisco-asa.log"] = new("cisco-asa", FullStory),
        ["fortigate.log"] = new("fortigate", FullStory),
        ["generic-kv.log"] = new("keyvalue", FullStory),
        ["huawei.log"] = new("huawei", FullStory),
        ["iptables-ufw.log"] = new("netfilter", [PortScan, Sweep, BruteForce, C2, FailedLogins],
            (Intrusion, "the netfilter LOG target has no signatures (failed logins are sshd lines of the same gateway syslog)")),
        ["json.log"] = new("json", FullStory),
        ["juniper-srx.log"] = new("juniper-srx", FullStory),
        ["leef.log"] = new("leef", FullStory),
        ["meraki.log"] = new("meraki", FullStory),
        ["mikrotik.log"] = new("mikrotik", [PortScan, BruteForce, C2, FailedLogins],
            (Intrusion, "RouterOS has no signature-based IPS, only firewall rules with action=log")),
        ["paloalto.log"] = new("paloalto", FullStory),
        ["pfsense.log"] = new("pfsense", [PortScan, Sweep, BruteForce, C2],
            (Intrusion, "filterlog only logs packet-filter decisions (Snort / Suricata packages write other logs)"),
            (FailedLogins, "filterlog only logs packet-filter decisions (GUI / sshd logins are other syslog programs)")),
        ["sonicwall.log"] = new("sonicwall", FullStory),
        ["sophos.log"] = new("sophos", FullStory),
        ["stormshield.log"] = new("stormshield", FullStory),
        ["watchguard.log"] = new("watchguard", FullStory),
        ["windows-firewall.log"] = new("windows-firewall", [PortScan, BruteForce, C2],
            (Intrusion, "pfirewall.log only has ALLOW / DROP lines of packets"),
            (FailedLogins, "Windows logons are in the Security event log (4625), not in pfirewall.log")),
        ["zyxel.log"] = new("zyxel", FullStory)
    };

    private static readonly LogParseContext Context = new(new DateTimeOffset(2026, 11, 22, 0, 0, 0, TimeSpan.Zero), TimeSpan.Zero);

    private static string Folder
    {
        get
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "samples", "firewall")))
                dir = dir.Parent;
            return Path.Combine((dir ?? throw new DirectoryNotFoundException("samples/firewall not found")).FullName, "samples", "firewall");
        }
    }

    public static TheoryData<string> SampleFiles()
    {
        var data = new TheoryData<string>();
        foreach (var path in Directory.GetFiles(Folder, "*.log").Order(StringComparer.Ordinal))
            data.Add(Path.GetFileName(path));
        return data;
    }

    private sealed record Run(string? Format, int Failed, List<string> FailedLines, List<DetectionEvent> Events, Dictionary<string, List<RuleHit>> Hits);

    /// <summary>The upload pipeline without the database (see LogProcessingWorker and DetectionEngine).</summary>
    private static Run Analyze(string file)
    {
        var lines = File.ReadAllLines(Path.Combine(Folder, file));
        var sample = lines.Where(l => !string.IsNullOrWhiteSpace(l)).Take(LogFormatDetector.SampleLines).ToList();
        var detection = LogFormatDetector.Detect(sample, Context);
        Assert.NotNull(detection.Format);

        var parser = new MultiFormatParser(detection.Format!, Context);
        var events = new List<DetectionEvent>();
        var failed = new List<string>();
        for (var i = 0; i < lines.Length; i++)
        {
            if (string.IsNullOrWhiteSpace(lines[i]))
                continue;
            var outcome = parser.Parse(lines[i], out var p);
            if (outcome == ParseOutcome.Failed)
                failed.Add($"line {i + 1}: {lines[i]}");
            else if (outcome == ParseOutcome.Parsed)
                events.Add(new DetectionEvent(i + 1, p!.ClientIp, p.Timestamp, p.Method, p.Url, p.StatusCode, p.UserAgent, p.Referrer, p.ResponseSize)
                {
                    DestinationIp = p.DestinationIp,
                    SourcePort = p.SourcePort,
                    DestinationPort = p.DestinationPort,
                    Transport = p.Transport,
                    Action = p.Action,
                    EventType = p.EventType,
                    RuleName = p.RuleName,
                    ThreatName = p.ThreatName
                });
        }

        var rules = DbSeeder.DefaultFirewallRules().ToList();
        for (var i = 0; i < rules.Count; i++)
            rules[i].Id = i + 1;
        var compiled = rules.Select(r =>
        {
            var c = DetectionCore.TryCompile(r, out var error);
            Assert.True(c is not null, $"{r.Name}: {error}");
            return c!;
        }).ToList();

        var core = new DetectionCore(compiled);
        foreach (var e in events.OrderBy(e => e.Timestamp).ThenBy(e => e.Id))
            core.Process(e);

        return new Run(detection.Format!.Id, failed.Count, failed, events,
            core.Hits.GroupBy(h => rules.Single(r => r.Id == h.RuleId).Name).ToDictionary(g => g.Key, g => g.ToList()));
    }

    private static Expected ExpectationFor(string file)
    {
        Assert.True(Expectations.TryGetValue(file, out var expected), $"{file} is not in the expected table: add its format and rules.");
        return expected!;
    }

    [Fact]
    public void Expected_table_and_folder_list_the_same_files() =>
        Assert.Equal(Expectations.Keys.Order(StringComparer.Ordinal),
            Directory.GetFiles(Folder, "*.log").Select(p => Path.GetFileName(p)!).Order(StringComparer.Ordinal));

    [Theory]
    [MemberData(nameof(SampleFiles))]
    public void Sample_is_detected_read_completely_and_fires_exactly_the_expected_rules(string file)
    {
        var expected = ExpectationFor(file);
        var run = Analyze(file);

        Assert.Equal(expected.Format, run.Format);
        Assert.True(run.Failed == 0, $"{file}: {run.Failed} line(s) not read, first: {run.FailedLines.FirstOrDefault()}");
        Assert.Equal(expected.Rules.Order(StringComparer.Ordinal), run.Hits.Keys.Order(StringComparer.Ordinal));
    }

    [Theory]
    [MemberData(nameof(SampleFiles))]
    public void Expected_table_has_the_mandatory_rules_and_a_reason_for_every_missing_one(string file)
    {
        var expected = ExpectationFor(file);
        foreach (var rule in Mandatory)
            Assert.Contains(rule, expected.Rules);
        Assert.Equal(FullStory.Except(expected.Rules).Order(StringComparer.Ordinal), expected.Without.Select(w => w.Rule).Order(StringComparer.Ordinal));
        Assert.All(expected.Without, w => Assert.False(string.IsNullOrWhiteSpace(w.Reason)));
        Assert.DoesNotContain(Flood, expected.Rules); // 100 blocked lines in a minute do not fit in a small sample
    }

    [Theory]
    [MemberData(nameof(SampleFiles))]
    public void Sample_has_no_copied_lines_and_is_in_time_order(string file)
    {
        var lines = File.ReadAllLines(Path.Combine(Folder, file));
        var copies = lines.GroupBy(l => l, StringComparer.Ordinal).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
        Assert.True(copies.Count == 0, $"{file}: line repeated: {copies.FirstOrDefault()}");

        var events = Analyze(file).Events;
        for (var i = 1; i < events.Count; i++)
            Assert.True(events[i].Timestamp >= events[i - 1].Timestamp, $"{file}: line {events[i].Id} is older than the event before it");
    }

    [Theory]
    [MemberData(nameof(SampleFiles))]
    public void Failed_login_alerts_come_from_six_different_attempts_within_five_minutes(string file)
    {
        var expected = ExpectationFor(file);
        var run = Analyze(file);
        if (!expected.Rules.Contains(FailedLogins))
        {
            Assert.DoesNotContain(run.Events, e => e.EventType == "auth");
            return;
        }
        var hit = Assert.Single(run.Hits[FailedLogins]);
        var evidence = run.Events.Where(e => hit.EventIds.Contains(e.Id)).ToList();
        Assert.True(evidence.Count >= 6, $"{file}: only {evidence.Count} failed logins");
        Assert.Equal(evidence.Count, evidence.Select(e => e.Timestamp).Distinct().Count());
        Assert.True(hit.Last - hit.First <= TimeSpan.FromMinutes(5));
    }

    /// <summary>A user who mistypes once and then signs in is in these samples on purpose: no alert for that address.</summary>
    [Theory]
    [InlineData("cisco-asa.log", "198.51.100.99")]
    [InlineData("paloalto.log", "198.51.100.99")]
    [InlineData("iptables-ufw.log", "10.0.0.12")]
    public void One_mistyped_password_is_not_an_alert(string file, string user)
    {
        var run = Analyze(file);
        var logins = run.Events.Where(e => e.ClientIp == user && e.EventType == "auth").ToList();
        Assert.Equal([FirewallAction.Deny, FirewallAction.Allow], logins.Select(e => e.Action!.Value));
        Assert.DoesNotContain(run.Hits[FailedLogins], h => h.Ip == user);
    }

    // ---------- only synthetic data ----------

    private static readonly Dictionary<string, string> AllowedSpecialAddresses = new(StringComparer.Ordinal)
    {
        ["0.0.0.0"] = "unspecified: 'no NAT address' (PAN-OS, Junos), 'no address' (Zyxel system message, GlobalProtect)",
        ["::"] = "unspecified IPv6 address in the PAN-OS GLOBALPROTECT line"
    };

    private static readonly IPNetwork[] AllowedNetworks =
    [
        IPNetwork.Parse("203.0.113.0/24"), IPNetwork.Parse("198.51.100.0/24"), IPNetwork.Parse("192.0.2.0/24"), // RFC 5737
        IPNetwork.Parse("2001:db8::/32"),                                                                      // RFC 3849
        IPNetwork.Parse("10.0.0.0/8"), IPNetwork.Parse("172.16.0.0/12"), IPNetwork.Parse("192.168.0.0/16")      // RFC 1918
    ];

    // Four numbers that are not part of a longer dotted number (the Junos "2636.1.1.1.2.129" is an enterprise OID).
    private static readonly Regex IPv4 = new(@"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\.?\d)", RegexOptions.CultureInvariant);
    private static readonly Regex IPv6Candidate = new(@"(?<![0-9A-Za-z:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Za-z:])", RegexOptions.CultureInvariant);
    private static readonly Regex Domain = new(@"\b(?:[a-z0-9-]+\.)+(?:com|net|org|info|io|eu|al|gov|edu)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static bool IsSynthetic(string text) =>
        AllowedSpecialAddresses.ContainsKey(text)
        || (IPAddress.TryParse(text, out var ip) && AllowedNetworks.Any(n => n.BaseAddress.AddressFamily == ip.AddressFamily && n.Contains(ip)));

    [Theory]
    [MemberData(nameof(SampleFiles))]
    public void Every_address_in_the_raw_lines_is_a_documentation_or_private_address(string file)
    {
        var n = 0;
        var found = 0;
        foreach (var line in File.ReadLines(Path.Combine(Folder, file)))
        {
            n++;
            foreach (Match m in IPv4.Matches(line))
            {
                found++;
                Assert.True(IsSynthetic(m.Value), $"{file}, line {n}: {m.Value}");
            }
            foreach (Match m in IPv6Candidate.Matches(line))
                if (IPAddress.TryParse(m.Value, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6)
                    Assert.True(IsSynthetic(m.Value), $"{file}, line {n}: {m.Value}");
            foreach (Match m in Domain.Matches(line))
                Assert.Matches(@"(?i)(^|\.)example\.(com|net|org)$", m.Value);
        }
        Assert.True(found > 50, $"{file}: only {found} addresses found, is the pattern still right?");
    }

    [Theory]
    [MemberData(nameof(SampleFiles))]
    public void Every_parsed_address_is_a_documentation_or_private_address(string file)
    {
        foreach (var e in Analyze(file).Events)
            foreach (var ip in new[] { e.ClientIp, e.DestinationIp })
                Assert.True(ip is null or "-" || IsSynthetic(ip), $"{file}, line {e.Id}: {ip}");
    }

    [Theory]
    [InlineData("2001:db8::5", true)]
    [InlineData("2001:db8:1::20", true)]
    [InlineData("2606:4700::1111", false)]
    [InlineData("192.0.2.44", true)]
    [InlineData("172.31.0.1", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("8.8.8.8", false)]
    [InlineData("203.0.114.1", false)]
    public void The_address_check_itself_works(string ip, bool synthetic) => Assert.Equal(synthetic, IsSynthetic(ip));

    [Fact]
    public void The_address_patterns_find_addresses_in_log_text()
    {
        Assert.Equal("203.0.113.9", IPv4.Match("From: 203.0.113.9.\",7101").Value);
        Assert.Equal("10.0.0.5", IPv4.Match("dst=10.0.0.5:80:X0").Value);
        Assert.DoesNotMatch(IPv4, "[junos@2636.1.1.1.2.129 ");
        Assert.Equal("2001:db8::5", IPv6Candidate.Match("[2001:db8::5]:41800->[2001:db8:1::1]:23").Value);
    }
}
