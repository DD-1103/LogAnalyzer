using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.ViewModels;

namespace LogAnalyzer.Tests;

/// <summary>
/// Review of the firewall rules (2026-11-25): the default rules on realistic benign traffic, rule semantics
/// (direction, replies, target hosts, connections) and form edge cases. Each test failed before its fix.
/// </summary>
public class FirewallRuleReviewTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 8, 0, 0, TimeSpan.Zero);
    private long _id;

    private DetectionEvent Fw(string src, double seconds, string? dst = "10.0.0.5", int? port = 443, int? sport = 50000,
        FirewallAction? action = FirewallAction.Allow, string? type = "traffic", string? threat = null) =>
        new(++_id, src, T0.AddSeconds(seconds), action?.ToString().ToUpperInvariant() ?? "-", "connection", 0, null, null)
        {
            DestinationIp = dst, DestinationPort = port, SourcePort = sport, Transport = port is null ? "icmp" : "tcp",
            Action = action, EventType = type, ThreatName = threat
        };

    private static DetectionCore Core(params DetectionRule[] rules) =>
        new(rules.Select((r, i) =>
        {
            r.Id = i + 1;
            return DetectionCore.TryCompile(r, out var error) ?? throw new InvalidOperationException(error);
        }).ToList());

    private static DetectionCore Run(IEnumerable<DetectionEvent> events, params DetectionRule[] rules)
    {
        var core = Core(rules);
        foreach (var e in events.OrderBy(e => e.Timestamp).ThenBy(e => e.Id))
            core.Process(e);
        return core;
    }

    private static DetectionRule Default(string name) => DbSeeder.DefaultFirewallRules().Single(r => r.Name == name);

    private static DetectionRule[] Defaults() => DbSeeder.DefaultFirewallRules().ToArray();

    private static string Names(DetectionCore core, DetectionRule[] rules) =>
        string.Join("; ", core.Hits.Select(h => rules[h.RuleId - 1].Name + " from " + h.Ip));

    private static void AssertQuiet(IEnumerable<DetectionEvent> events)
    {
        var rules = Defaults();
        Assert.Equal("", Names(Run(events, rules), rules));
    }

    private const string C2 = "Connection to backdoor / C2 port";
    private const string Scan = "Port scan";
    private const string Sweep = "Network sweep";
    private const string Brute = "Brute force on remote-access services";
    private const string Logins = "Repeated failed logins on the firewall / VPN";

    // ------------------------------------------------------------------ Suspicious outbound: direction

    [Theory]
    [InlineData("198.51.100.9", FirewallAction.Drop)]   // internet background noise: one blocked probe of 4444
    [InlineData("198.51.100.9", FirewallAction.Allow)]
    [InlineData("8.8.4.4", FirewallAction.Deny)]
    [InlineData("2001:db8::9", FirewallAction.Drop)]
    public void An_outside_host_that_probes_a_backdoor_port_is_not_suspicious_outbound(string source, FirewallAction action) =>
        Assert.Empty(Run([Fw(source, 0, dst: "10.0.1.10", port: 4444, action: action)], Default(C2)).Hits);

    [Theory]
    [InlineData("10.0.0.23")]
    [InlineData("172.16.4.4")]
    [InlineData("172.31.255.1")]
    [InlineData("192.168.56.10")]
    [InlineData("100.64.0.9")]
    [InlineData("169.254.10.1")]
    [InlineData("fd00::23")]
    [InlineData("fe80::23")]
    public void An_inside_host_that_connects_to_a_backdoor_port_is(string source)
    {
        foreach (var action in new[] { FirewallAction.Allow, FirewallAction.Deny })
            Assert.Equal(source, Assert.Single(Run([Fw(source, 0, dst: "198.51.100.200", port: 4444, action: action)], Default(C2)).Hits).Ip);
    }

    [Theory]
    [InlineData("172.15.0.1")]
    [InlineData("172.32.0.1")]
    [InlineData("11.0.0.1")]
    [InlineData("192.169.0.1")]
    [InlineData("100.128.0.1")]
    [InlineData("not-an-ip")]
    [InlineData("-")]
    public void Addresses_next_to_the_private_ranges_are_not_inside(string source) =>
        Assert.Empty(Run([Fw(source, 0, dst: "198.51.100.200", port: 4444)], Default(C2)).Hits);

    // ------------------------------------------------------------------ Replies in flow logs

    /// <summary>Flow logs (AWS VPC) and packet logs write both directions: request, then reply with the ports swapped.</summary>
    private IEnumerable<DetectionEvent> Conversation(string client, int clientPort, string server, int serverPort, double at, bool replyFirst = false)
    {
        var request = () => Fw(client, at, dst: server, port: serverPort, sport: clientPort);
        var reply = () => Fw(server, at, dst: client, port: clientPort, sport: serverPort);
        return replyFirst ? new[] { reply(), request() } : [request(), reply()];
    }

    [Theory]
    [InlineData(443, false)]
    [InlineData(443, true)]   // same second: the reply line may come first
    [InlineData(8080, false)]
    public void A_server_that_answers_one_busy_client_is_not_a_port_scanner(int serverPort, bool replyFirst)
    {
        // A load balancer / NAT gateway opens 60 connections per minute; every reply goes to another client port.
        var events = Enumerable.Range(0, 60)
            .SelectMany(i => Conversation("10.0.0.7", 1024 + i * 997 % 60000, "10.0.1.10", serverPort, i, replyFirst)).ToList();
        AssertQuiet(events);
    }

    [Fact]
    public void A_server_that_answers_many_clients_is_not_a_sweeper()
    {
        var rule = new DetectionRule
        {
            Name = "sweep", AppliesTo = LogSource.Firewall, Kind = RuleKind.DistinctCount, Field = RuleField.DestinationIp,
            Threshold = 20, WindowSeconds = 120
        };
        var events = Enumerable.Range(0, 80).SelectMany(i => Conversation($"198.51.100.{i + 1}", 40000 + i, "10.0.1.10", 443, i)).ToList();
        Assert.Empty(Run(events, rule).Hits);
    }

    [Theory]
    [InlineData(9001)]
    [InlineData(3333)]
    [InlineData(4444)]
    public void A_reply_to_a_client_port_is_not_a_connection_to_a_backdoor_port(int clientPort) =>
        AssertQuiet(Conversation("198.51.100.7", clientPort, "10.0.1.10", 443, 0));

    [Fact]
    public void A_scan_from_a_well_known_source_port_is_still_a_scan()
    {
        // nmap -g 53: no host ever asked this source anything, so its packets are not replies.
        var events = Enumerable.Range(0, 30).Select(i => Fw("203.0.113.5", i, port: 2000 + i, sport: 53, action: FirewallAction.Drop)).ToList();
        Assert.Equal(30, Assert.Single(Run(events, Default(Scan)).Hits).EventIds.Count);
    }

    [Fact]
    public void A_blocked_request_does_not_turn_a_later_scan_into_replies()
    {
        var events = new List<DetectionEvent> { Fw("10.0.0.5", 0, dst: "203.0.113.5", port: 443, action: FirewallAction.Deny) };
        events.AddRange(Enumerable.Range(0, 30).Select(i => Fw("203.0.113.5", 1 + i, port: 2000 + i, sport: 443, action: FirewallAction.Drop)));
        Assert.Equal(30, Assert.Single(Run(events, Default(Scan)).Hits).EventIds.Count);
    }

    // ------------------------------------------------------------------ Port scan: many ports of ONE host

    [Fact]
    public void A_nat_gateway_that_uses_many_services_is_not_a_port_scanner()
    {
        // 300 users behind one address: 30 different services on 30 different servers per minute, two ports per server.
        var events = Enumerable.Range(0, 120)
            .Select(i => Fw("10.0.0.1", i * 0.5, dst: $"198.51.100.{i % 30 + 1}", port: new[] { 443, 1000 + i % 30 }[i % 2], sport: 20000 + i)).ToList();
        AssertQuiet(events);
    }

    [Fact]
    public void A_peer_to_peer_client_is_not_a_port_scanner()
    {
        var events = Enumerable.Range(0, 200) // every peer listens on its own random port
            .Select(i => Fw("10.0.0.31", i * 0.3, dst: $"203.0.113.{i % 100 + 1}", port: 20000 + i % 100 * 311, sport: 51413)).ToList();
        AssertQuiet(events);
    }

    [Fact]
    public void A_scan_of_two_hosts_is_found_on_each_of_them()
    {
        var events = Enumerable.Range(0, 40).Select(i => Fw("203.0.113.5", i, dst: "10.0.0." + (5 + i % 2), port: 100 + i / 2)).ToList();
        var hit = Assert.Single(Run(events, Default(Scan)).Hits); // one alert per source, evidence of both hosts
        Assert.Equal(40, hit.EventIds.Count);
    }

    // ------------------------------------------------------------------ Network sweep: ordinary clients contact many hosts

    [Fact]
    public void Ordinary_browsing_is_not_a_network_sweep() =>
        AssertQuiet(Enumerable.Range(0, 60).Select(i => Fw("10.0.0.21", i, dst: $"198.51.100.{i + 1}", sport: 50000 + i)).ToList());

    [Fact]
    public void A_dns_resolver_and_a_mail_server_are_not_sweepers() =>
        AssertQuiet(Enumerable.Range(0, 300).SelectMany(i => new[]
        {
            Fw("10.0.0.2", i * 0.3, dst: $"198.51.{i / 250}.{i % 250 + 1}", port: 53, sport: 10000 + i),
            Fw("10.0.0.3", i * 0.3, dst: $"203.0.{113 + i / 250}.{i % 250 + 1}", port: 25, sport: 20000 + i)
        }).ToList());

    [Fact]
    public void A_monitoring_or_backup_host_that_reaches_40_servers_is_neither_a_sweeper_nor_a_brute_forcer() =>
        AssertQuiet(Enumerable.Range(0, 40).SelectMany(i => new[]
        {
            Fw("10.0.0.250", i * 0.05, dst: $"10.0.5.{10 + i}", port: null, sport: null),
            Fw("10.0.0.250", i * 0.05, dst: $"10.0.5.{10 + i}", port: 22, sport: 40000 + i),
            Fw("10.0.0.250", i * 0.05, dst: $"10.0.5.{10 + i}", port: 445, sport: 41000 + i)
        }).ToList());

    [Fact]
    public void A_blocked_sweep_is_found_by_the_sweep_rule_only()
    {
        var events = Enumerable.Range(0, 50).Select(i => Fw("203.0.113.60", i * 1.5, dst: $"10.0.3.{i + 1}", port: 445, sport: 40000 + i,
            action: FirewallAction.Drop)).ToList();
        var rules = Defaults();
        var core = Run(events, rules);
        Assert.Equal(Sweep + " from 203.0.113.60", Names(core, rules)); // used to raise "Brute force" as well
        Assert.Equal(50, core.Hits.Single().EventIds.Count);
    }

    // ------------------------------------------------------------------ Brute force: connections to one host

    [Fact]
    public void Retransmitted_packets_of_a_few_connections_are_not_a_brute_force()
    {
        // A blocked client: 6 attempts, each SYN logged 5 times (same source port).
        var events = Enumerable.Range(0, 30).Select(i => Fw("10.0.0.44", i * 5, dst: "10.0.1.20", port: 445, sport: 50000 + i / 5,
            action: FirewallAction.Drop)).ToList();
        AssertQuiet(events);
    }

    [Fact]
    public void Start_and_end_records_of_a_session_count_once()
    {
        var events = Enumerable.Range(0, 12).SelectMany(i => new[]
        {
            Fw("10.0.0.40", i * 20, dst: "10.0.1.20", port: 22, sport: 50000 + i),
            Fw("10.0.0.40", i * 20 + 10, dst: "10.0.1.20", port: 22, sport: 50000 + i)
        }).ToList();
        AssertQuiet(events);
    }

    [Fact]
    public void Twenty_connections_to_one_host_are_a_brute_force_and_all_their_lines_are_evidence()
    {
        var events = Enumerable.Range(0, 20).SelectMany(i => new[]
        {
            Fw("203.0.113.9", i * 10, dst: "10.0.1.20", port: 22, sport: 40000 + i),
            Fw("203.0.113.9", i * 10 + 4, dst: "10.0.1.20", port: 22, sport: 40000 + i)
        }).ToList();
        Assert.Empty(Run(events.Take(38), Default(Brute)).Hits); // 19 connections
        Assert.Equal(39, Assert.Single(Run(events.Take(39), Default(Brute)).Hits).EventIds.Count);
        Assert.Equal(40, Assert.Single(Run(events, Default(Brute)).Hits).EventIds.Count);
    }

    [Fact]
    public void Connections_without_a_source_port_are_counted_one_by_one()
    {
        var events = Enumerable.Range(0, 20).Select(i => Fw("203.0.113.9", i * 10, dst: "10.0.1.20", port: 22, sport: null)).ToList();
        Assert.Empty(Run(events.Take(19), Default(Brute)).Hits);
        Assert.Equal(20, Assert.Single(Run(events, Default(Brute)).Hits).EventIds.Count);
    }

    // ------------------------------------------------------------------ Failed logins

    [Fact]
    public void Failed_logins_logged_as_dropped_count_too()
    {
        // CEF / LEEF keep the device's own word: act=drop on a login event.
        var events = Enumerable.Range(0, 6).Select(i => Fw("198.51.100.7", i * 20, type: "auth", action: FirewallAction.Drop)).ToList();
        Assert.Equal(6, Assert.Single(Run(events, Default(Logins)).Hits).EventIds.Count);
    }

    // ------------------------------------------------------------------ Form

    [Fact]
    public void An_undefined_action_value_is_rejected_instead_of_silently_meaning_any_action()
    {
        var model = new RuleFormModel
        {
            Name = "x", AppliesTo = LogSource.Firewall, Kind = RuleKind.Threshold, Threshold = 5, WindowSeconds = 60,
            Actions = [(FirewallAction)99]
        };
        model.Normalize();
        Assert.Contains(RuleValidator.Validate(model.ToRule()), e => e.Contains("Action filter"));
    }

    [Fact]
    public void A_distinct_port_rule_whose_port_filter_lists_too_few_ports_is_rejected()
    {
        DetectionRule Rule(string ports) => new()
        {
            Name = "x", AppliesTo = LogSource.Firewall, Kind = RuleKind.DistinctCount, Field = RuleField.DestinationPort,
            Threshold = 5, WindowSeconds = 60, PortFilter = ports
        };
        Assert.Contains(RuleValidator.Validate(Rule("22,23,3389,22-23")), e => e.Contains("can never"));
        Assert.Empty(RuleValidator.Validate(Rule("22,23,3389,5900-5901")));
        var hosts = Rule("22");
        hosts.Field = RuleField.DestinationIp; // a sweep of one port is fine
        Assert.Empty(RuleValidator.Validate(hosts));
    }
}
