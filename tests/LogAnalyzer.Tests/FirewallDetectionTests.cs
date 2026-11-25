using System.Diagnostics;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.ViewModels;

namespace LogAnalyzer.Tests;

/// <summary>Firewall detection: port/action filters, firewall fields, threshold and distinct-count rules, default rules.</summary>
public class FirewallDetectionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 8, 0, 0, TimeSpan.Zero);
    private long _id;

    private DetectionEvent Fw(string src, double seconds, string? dst = "10.0.0.5", int? port = 443,
        FirewallAction? action = FirewallAction.Allow, string? type = "traffic", string message = "connection",
        string? threat = null, string? ruleName = "policy-1") =>
        new(++_id, src, T0.AddSeconds(seconds), action?.ToString().ToUpperInvariant() ?? "-", message, 0, null, null)
        {
            DestinationIp = dst,
            DestinationPort = port,
            Transport = "tcp",
            Action = action,
            EventType = type,
            ThreatName = threat,
            RuleName = ruleName
        };

    private static DetectionCore Core(params DetectionRule[] rules) =>
        new(rules.Select((r, i) =>
        {
            r.Id = i + 1;
            return DetectionCore.TryCompile(r, out var error) ?? throw new InvalidOperationException(error);
        }).ToList());

    private static DetectionRule Rule(RuleKind kind, RuleField field = RuleField.Message, string? pattern = null,
        int? threshold = null, int? window = null, string? actions = null, string? ports = null) => new()
    {
        Name = "test",
        AppliesTo = LogSource.Firewall,
        Kind = kind,
        Field = field,
        Pattern = pattern,
        Threshold = threshold,
        WindowSeconds = window,
        ActionFilter = actions,
        PortFilter = ports,
        AttackType = AttackType.PortScan,
        Severity = Severity.High
    };

    private static DetectionRule Default(string name) => DbSeeder.DefaultFirewallRules().Single(r => r.Name == name);

    private static DetectionCore Run(DetectionCore core, IEnumerable<DetectionEvent> events)
    {
        foreach (var e in events.OrderBy(e => e.Timestamp).ThenBy(e => e.Id))
            core.Process(e);
        return core;
    }

    // ------------------------------------------------------------------ PortSet / ActionSet

    [Fact]
    public void PortSet_parses_ports_and_ranges()
    {
        Assert.True(PortSet.TryParse("22, 23,3389,5900-5902", out var set, out var error));
        Assert.Null(error);
        Assert.NotNull(set);
        foreach (var p in new[] { 22, 23, 3389, 5900, 5901, 5902 })
            Assert.True(set.Contains(p), p.ToString());
        foreach (var p in new[] { 0, 21, 24, 3388, 5899, 5903, 65535, -1, 70000 })
            Assert.False(set.Contains(p), p.ToString());
        Assert.False(set.Contains((int?)null));
        Assert.Equal("22,23,3389,5900-5902", set.ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(" , ,")]
    public void PortSet_blank_means_any_port(string? text)
    {
        Assert.True(PortSet.TryParse(text, out var set, out var error));
        Assert.Null(set);
        Assert.Null(error);
    }

    [Fact]
    public void PortSet_accepts_edges_and_single_port_ranges()
    {
        Assert.True(PortSet.TryParse("0,65535,80-80,", out var set, out _));
        Assert.True(set!.Contains(0));
        Assert.True(set.Contains(65535));
        Assert.True(set.Contains(80));
        Assert.Equal("0,65535,80", set.ToString());
    }

    [Theory]
    [InlineData("70000", "'70000' is not a port")]
    [InlineData("22,ssh", "'ssh' is not a port")]
    [InlineData("+22", "'+22' is not a port")]
    [InlineData("99999999999", "is not a port")]
    [InlineData("5902-5900", "'5902-5900' is not a valid range")]
    [InlineData("-5", "'-5' is not a port range")]
    [InlineData("1-2-3", "is not a port range")]
    [InlineData("1000-70000", "is not a port range")]
    public void PortSet_rejects_invalid_text(string text, string expected)
    {
        Assert.False(PortSet.TryParse(text, out var set, out var error));
        Assert.Null(set);
        Assert.StartsWith("Port filter:", error);
        Assert.Contains(expected, error);
    }

    [Fact]
    public void PortSet_limits_the_number_of_entries()
    {
        var ok = string.Join(",", Enumerable.Range(1, PortSet.MaxEntries));
        Assert.True(PortSet.TryParse(ok, out _, out _));
        var tooMany = string.Join(",", Enumerable.Range(1, PortSet.MaxEntries + 1));
        Assert.False(PortSet.TryParse(tooMany, out _, out var error));
        Assert.Contains("at most", error);
    }

    [Fact]
    public void ActionSet_parses_names_case_insensitively()
    {
        Assert.True(ActionSet.TryParse(" deny, DROP,Reject,deny ", out var set, out var error));
        Assert.Null(error);
        Assert.True(set!.Contains(FirewallAction.Deny));
        Assert.True(set.Contains(FirewallAction.Drop));
        Assert.True(set.Contains(FirewallAction.Reject));
        Assert.False(set.Contains(FirewallAction.Allow));
        Assert.False(set.Contains(FirewallAction.Alert));
        Assert.False(set.Contains(null));
        Assert.Equal("Deny,Drop,Reject", set.ToString());
    }

    [Fact]
    public void ActionSet_unknown_matches_events_without_an_action()
    {
        Assert.True(ActionSet.TryParse("Unknown", out var set, out _));
        Assert.True(set!.Contains(null));
        Assert.True(set.Contains(FirewallAction.Unknown));
    }

    [Theory]
    [InlineData("Block")]
    [InlineData("2")]
    [InlineData("Deny|Drop")]
    [InlineData("Deny,Allow Drop")]
    public void ActionSet_rejects_unknown_names(string text)
    {
        Assert.False(ActionSet.TryParse(text, out var set, out var error));
        Assert.Null(set);
        Assert.StartsWith("Action filter:", error);
        Assert.Contains("is not a firewall action", error);
    }

    [Fact]
    public void ActionSet_blank_means_any_action()
    {
        Assert.True(ActionSet.TryParse(" ", out var set, out var error));
        Assert.Null(set);
        Assert.Null(error);
    }

    [Fact]
    public void TryCompile_reports_filter_and_kind_errors()
    {
        var badPort = Rule(RuleKind.Threshold, threshold: 5, window: 60, ports: "22,70000");
        Assert.Null(DetectionCore.TryCompile(badPort, out var error));
        Assert.Equal("Port filter: '70000' is not a port (use numbers 0-65535 or ranges like 5900-5902).", error);

        Assert.Null(DetectionCore.TryCompile(Rule(RuleKind.Threshold, threshold: 5, window: 60, actions: "Deny,Nope"), out error));
        Assert.Contains("'Nope' is not a firewall action", error);

        Assert.Null(DetectionCore.TryCompile(Rule(RuleKind.DistinctCount, RuleField.DestinationPort, threshold: 1, window: 60), out error));
        Assert.Contains("at least 2", error);

        var webDistinct = Rule(RuleKind.DistinctCount, RuleField.DestinationPort, threshold: 5, window: 60);
        webDistinct.AppliesTo = LogSource.WebAccess;
        Assert.Null(DetectionCore.TryCompile(webDistinct, out error));
        Assert.Contains("only run on firewall logs", error);

        var firewallAnomaly = Rule(RuleKind.Anomaly, threshold: 20);
        Assert.Null(DetectionCore.TryCompile(firewallAnomaly, out error));
        Assert.Contains("only run on web access logs", error);

        var ok = DetectionCore.TryCompile(Rule(RuleKind.Threshold, threshold: 5, window: 60, actions: "deny", ports: "22"), out error);
        Assert.Null(error);
        Assert.NotNull(ok!.Ports);
        Assert.NotNull(ok.Actions);
    }

    // ------------------------------------------------------------------ Signature rules on firewall fields

    [Theory]
    [InlineData(RuleField.ThreatName, "(?i)eternalblue")]
    [InlineData(RuleField.RuleName, "^block-inbound$")]
    [InlineData(RuleField.EventType, "^threat$")]
    [InlineData(RuleField.DestinationPort, "^445$")]
    [InlineData(RuleField.DestinationIp, @"^10\.0\.0\.7$")]
    [InlineData(RuleField.Message, "SMB exploit attempt")]
    public void Signature_matches_each_firewall_field(RuleField field, string pattern)
    {
        var core = Core(Rule(RuleKind.Signature, field, pattern));
        core.Process(Fw("203.0.113.9", 0, dst: "10.0.0.7", port: 445, action: FirewallAction.Deny, type: "threat",
            message: "SMB exploit attempt", threat: "ET EXPLOIT EternalBlue", ruleName: "block-inbound"));
        core.Process(Fw("203.0.113.10", 1, dst: "10.0.0.8", port: 443, type: "traffic", message: "normal", ruleName: "allow-web"));

        var hit = Assert.Single(core.Hits);
        Assert.Equal("203.0.113.9", hit.Ip);
        Assert.Single(hit.EventIds);
    }

    [Fact]
    public void Signature_on_a_missing_field_never_matches()
    {
        var core = Core(Rule(RuleKind.Signature, RuleField.ThreatName, ".*")); // ".*" would match an empty string
        core.Process(Fw("203.0.113.9", 0, threat: null));
        Assert.Empty(core.Hits);
    }

    [Fact]
    public void Firewall_message_is_not_url_decoded_but_web_urls_still_are()
    {
        var fw = Core(Rule(RuleKind.Signature, RuleField.Message, "%27"));
        fw.Process(Fw("203.0.113.9", 0, message: "payload %27 OR 1=1"));
        Assert.Single(fw.Hits);

        var web = Core(new DetectionRule { Name = "w", Kind = RuleKind.Signature, Field = RuleField.Url, Pattern = "' OR" });
        web.Process(new DetectionEvent(1, "198.51.100.1", T0, "GET", "/a?id=1%27%20OR%201=1", 200, "ua", null));
        Assert.Single(web.Hits);
    }

    [Fact]
    public void Action_and_port_filters_apply_to_signature_rules()
    {
        var rule = Rule(RuleKind.Signature, RuleField.ThreatName, ".+", actions: "Deny,Drop", ports: "445,3389");
        var core = Core(rule);
        core.Process(Fw("203.0.113.1", 0, port: 445, action: FirewallAction.Deny, threat: "x"));   // match
        core.Process(Fw("203.0.113.2", 1, port: 445, action: FirewallAction.Alert, threat: "x"));  // action
        core.Process(Fw("203.0.113.3", 2, port: 80, action: FirewallAction.Drop, threat: "x"));    // port
        core.Process(Fw("203.0.113.4", 3, port: null, action: FirewallAction.Drop, threat: "x"));  // no port
        core.Process(Fw("203.0.113.5", 4, port: 3389, action: null, threat: "x"));                  // no action
        Assert.Equal("203.0.113.1", Assert.Single(core.Hits).Ip);
    }

    // ------------------------------------------------------------------ Threshold rules on firewall logs

    [Fact]
    public void Threshold_counts_filtered_events_per_source_in_the_window()
    {
        var rule = Rule(RuleKind.Threshold, threshold: 5, window: 60, actions: "Deny", ports: "22");
        var events = new List<DetectionEvent>();
        for (var i = 0; i < 4; i++)
            events.Add(Fw("203.0.113.1", i * 10, port: 22, action: FirewallAction.Deny));
        events.Add(Fw("203.0.113.1", 41, port: 22, action: FirewallAction.Allow)); // wrong action
        events.Add(Fw("203.0.113.1", 42, port: 23, action: FirewallAction.Deny));  // wrong port
        events.Add(Fw("203.0.113.2", 43, port: 22, action: FirewallAction.Deny));  // other source

        var core = Run(Core(rule), events);
        Assert.Empty(core.Hits);

        core.Process(Fw("203.0.113.1", 50, port: 22, action: FirewallAction.Deny)); // 5th matching event
        var hit = Assert.Single(core.Hits);
        Assert.Equal("203.0.113.1", hit.Ip);
        Assert.Equal(5, hit.EventIds.Count);
    }

    [Fact]
    public void Threshold_window_expires()
    {
        var rule = Rule(RuleKind.Threshold, threshold: 3, window: 60);
        var core = Run(Core(rule), [Fw("203.0.113.1", 0), Fw("203.0.113.1", 50), Fw("203.0.113.1", 120), Fw("203.0.113.1", 200)]);
        Assert.Empty(core.Hits);
    }

    [Fact]
    public void Threshold_ignores_http_filters_and_uses_pattern_and_path_pattern_on_firewall_rules()
    {
        var rule = Rule(RuleKind.Threshold, RuleField.EventType, "^auth$", threshold: 3, window: 300);
        rule.MethodFilter = "POST";  // would never match a firewall event: ignored
        rule.StatusFilter = 404;     // firewall events have status 0: ignored
        rule.PathPattern = "(?i)login failed";
        var core = Run(Core(rule),
        [
            Fw("203.0.113.1", 0, type: "auth", message: "VPN login failed for admin"),
            Fw("203.0.113.1", 10, type: "auth", message: "VPN login succeeded for admin"), // path pattern
            Fw("203.0.113.1", 20, type: "traffic", message: "login failed"),               // pattern
            Fw("203.0.113.1", 30, type: "auth", message: "Admin login failed"),
            Fw("203.0.113.1", 40, type: "auth", message: "SSL-VPN LOGIN FAILED")
        ]);
        Assert.Equal(3, Assert.Single(core.Hits).EventIds.Count);
    }

    [Fact]
    public void Per_source_rules_skip_events_without_a_source()
    {
        var threshold = Rule(RuleKind.Threshold, threshold: 2, window: 60);
        var distinct = Rule(RuleKind.DistinctCount, RuleField.DestinationPort, threshold: 2, window: 60);
        var core = Run(Core(threshold, distinct), [Fw("-", 0, port: 1), Fw("-", 1, port: 2), Fw("", 2, port: 3), Fw("", 3, port: 4)]);
        Assert.Empty(core.Hits);
    }

    [Fact]
    public void Web_threshold_rule_still_uses_method_and_status_filters()
    {
        var rule = new DetectionRule { Name = "w", Kind = RuleKind.Threshold, StatusFilter = 404, Threshold = 2, WindowSeconds = 60 };
        var core = Core(rule);
        core.Process(new DetectionEvent(1, "198.51.100.1", T0, "GET", "/a", 404, "ua", null));
        core.Process(new DetectionEvent(2, "198.51.100.1", T0.AddSeconds(1), "GET", "/b", 200, "ua", null));
        Assert.Empty(core.Hits);
        core.Process(new DetectionEvent(3, "198.51.100.1", T0.AddSeconds(2), "GET", "/c", 404, "ua", null));
        Assert.Equal(2, Assert.Single(core.Hits).EventIds.Count);
    }

    // ------------------------------------------------------------------ Distinct-count rules

    [Fact]
    public void Distinct_count_triggers_at_exactly_n_distinct_values()
    {
        var core = Core(Rule(RuleKind.DistinctCount, RuleField.DestinationPort, threshold: 15, window: 60));
        for (var port = 1; port <= 14; port++)
            core.Process(Fw("203.0.113.50", port, port: port, action: FirewallAction.Deny));
        Assert.Empty(core.Hits); // N - 1

        core.Process(Fw("203.0.113.50", 15, port: 15, action: FirewallAction.Deny));
        var hit = Assert.Single(core.Hits);
        Assert.Equal(15, hit.EventIds.Count);
        Assert.Equal(T0.AddSeconds(1), hit.First);
        Assert.Equal(T0.AddSeconds(15), hit.Last);
    }

    [Fact]
    public void Distinct_count_ignores_repeated_values()
    {
        var core = Core(Rule(RuleKind.DistinctCount, RuleField.DestinationPort, threshold: 15, window: 60));
        for (var i = 0; i < 56; i++)
            core.Process(Fw("203.0.113.50", i, port: 1 + i % 14)); // 56 events, 14 different ports
        Assert.Empty(core.Hits);
    }

    [Fact]
    public void Distinct_count_window_expires()
    {
        var core = Core(Rule(RuleKind.DistinctCount, RuleField.DestinationPort, threshold: 15, window: 60));
        for (var i = 0; i < 10; i++)
            core.Process(Fw("203.0.113.50", i, port: 100 + i));
        for (var i = 0; i < 10; i++)
            core.Process(Fw("203.0.113.50", 100 + i, port: 200 + i)); // first ten are out of the window by now
        Assert.Empty(core.Hits);
    }

    [Fact]
    public void Distinct_count_counts_per_source()
    {
        var core = Core(Rule(RuleKind.DistinctCount, RuleField.DestinationPort, threshold: 15, window: 60));
        for (var i = 0; i < 10; i++)
        {
            core.Process(Fw("203.0.113.1", i, port: 1000 + i));
            core.Process(Fw("203.0.113.2", i, port: 2000 + i));
        }
        Assert.Empty(core.Hits);
    }

    [Fact]
    public void Distinct_count_evidence_is_the_window_including_repeats()
    {
        var core = Core(Rule(RuleKind.DistinctCount, RuleField.DestinationPort, threshold: 3, window: 60));
        var a = Fw("203.0.113.1", 0, port: 1);
        var b = Fw("203.0.113.1", 10, port: 1);   // repeat: in the window, so evidence
        var c = Fw("203.0.113.1", 20, port: 2);
        var d = Fw("203.0.113.1", 30, port: 3);   // 3rd distinct port: trigger
        var e = Fw("203.0.113.1", 200, port: 1);  // window restarts: only 1 distinct
        var f = Fw("203.0.113.1", 201, port: 1);
        var g = Fw("203.0.113.1", 202, port: 2);
        Run(core, [a, b, c, d, e, f, g]);
        Assert.Equal(new[] { a.Id, b.Id, c.Id, d.Id }, Assert.Single(core.Hits).EventIds.Order());

        var h = Fw("203.0.113.1", 203, port: 3); // second burst reaches 3 distinct: e..h become evidence
        core.Process(h);
        Assert.Equal(new[] { a.Id, b.Id, c.Id, d.Id, e.Id, f.Id, g.Id, h.Id }, Assert.Single(core.Hits).EventIds.Order());

        core.Process(Fw("203.0.113.1", 204, port: 2)); // still >= 3 distinct in the window: added
        Assert.Equal(9, Assert.Single(core.Hits).EventIds.Count);
    }

    [Fact]
    public void Distinct_count_on_destination_ip_detects_a_sweep_with_filters()
    {
        var rule = Rule(RuleKind.DistinctCount, RuleField.DestinationIp, threshold: 20, window: 120, ports: "445", actions: "Deny,Drop");
        var events = new List<DetectionEvent>();
        for (var i = 1; i <= 25; i++)
            events.Add(Fw("203.0.113.60", i * 4, dst: $"10.0.1.{i}", port: 445, action: FirewallAction.Drop));
        for (var i = 1; i <= 25; i++)
            events.Add(Fw("203.0.113.61", i * 4, dst: $"10.0.2.{i}", port: 443, action: FirewallAction.Drop)); // wrong port
        var core = Run(Core(rule), events);
        var hit = Assert.Single(core.Hits);
        Assert.Equal("203.0.113.60", hit.Ip);
        Assert.Equal(25, hit.EventIds.Count);
    }

    [Fact]
    public void Distinct_count_with_a_pattern_counts_only_matching_values()
    {
        var rule = Rule(RuleKind.DistinctCount, RuleField.DestinationIp, @"^10\.", threshold: 5, window: 60);
        var events = Enumerable.Range(1, 10).Select(i => Fw("10.0.0.50", i, dst: $"8.8.{i}.1")).ToList(); // external
        var core = Run(Core(rule), events);
        Assert.Empty(core.Hits);
        Run(core, Enumerable.Range(1, 5).Select(i => Fw("10.0.0.50", 20 + i, dst: $"10.9.0.{i}")));
        Assert.Equal(5, Assert.Single(core.Hits).EventIds.Count);
    }

    [Fact]
    public void Distinct_count_runs_in_linear_time()
    {
        // 200k events in 200 s from one scanner (60k events per window) plus 200k from 2,000 quiet sources:
        // re-copying the window on every event would be ~10^10 operations.
        var core = Core(Rule(RuleKind.DistinctCount, RuleField.DestinationPort, threshold: 15, window: 60));
        var sw = Stopwatch.StartNew();
        for (var i = 0; i < 200_000; i++)
        {
            core.Process(new DetectionEvent(i, "203.0.113.99", T0.AddMilliseconds(i), "DENY", "scan", 0, null, null)
                { DestinationPort = 1 + i % 1000, Action = FirewallAction.Deny });
            core.Process(new DetectionEvent(1_000_000 + i, "10.1." + (i % 2000 / 250) + "." + (i % 250), T0.AddMilliseconds(i),
                "ALLOW", "web", 0, null, null) { DestinationPort = 443, Action = FirewallAction.Allow });
        }
        sw.Stop();

        var hit = Assert.Single(core.Hits);
        Assert.Equal("203.0.113.99", hit.Ip);
        Assert.Equal(200_000, hit.EventIds.Count);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"took {sw.Elapsed}");
    }

    // ------------------------------------------------------------------ Default firewall rules

    [Fact]
    public void Default_firewall_rules_compile_and_validate()
    {
        var rules = DbSeeder.DefaultFirewallRules().ToList();
        Assert.Equal(7, rules.Count);
        Assert.Equal(rules.Count, rules.Select(r => r.Name).Distinct().Count());
        foreach (var rule in rules)
        {
            Assert.Equal(LogSource.Firewall, rule.AppliesTo);
            Assert.NotNull(DetectionCore.TryCompile(rule, out var error));
            Assert.Null(error);
            Assert.Empty(RuleValidator.Validate(rule));
            Assert.True(rule.Description is { Length: > 40 and <= 1000 }, rule.Name);
            Assert.True(LogAnalyzer.Web.Helpers.Format.IsNetworkAttack(rule.AttackType) || rule.AttackType == AttackType.BruteForce, rule.Name);
        }
        // No name clashes with the web defaults (both sets share the unique Name index).
        Assert.Empty(rules.Select(r => r.Name).Intersect(DbSeeder.DefaultRules().Select(r => r.Name), StringComparer.OrdinalIgnoreCase));
    }

    [Fact]
    public void New_attack_types_have_readable_labels()
    {
        foreach (var type in Enum.GetValues<AttackType>())
            Assert.False(string.IsNullOrWhiteSpace(LogAnalyzer.Web.Helpers.Format.AttackLabel(type)));
        Assert.Equal("Port scan", LogAnalyzer.Web.Helpers.Format.AttackLabel(AttackType.PortScan));
        Assert.Equal("Authentication failure", LogAnalyzer.Web.Helpers.Format.AttackLabel(AttackType.AuthenticationFailure));
        Assert.Equal("Destination port", LogAnalyzer.Web.Helpers.Format.FieldLabel(RuleField.DestinationPort));
    }

    [Fact]
    public void Seeding_skips_names_that_already_exist()
    {
        Assert.Equal(7, DbSeeder.FirewallRulesToSeed([]).Count);
        var missing = DbSeeder.FirewallRulesToSeed(["port SCAN", "Network sweep", "Some admin rule"]);
        Assert.Equal(5, missing.Count);
        Assert.DoesNotContain(missing, r => r.Name is "Port scan" or "Network sweep");
    }

    /// <summary>Ordinary traffic: browsing clients, an admin SSH session, one mistyped VPN password, background noise.</summary>
    private List<DetectionEvent> NormalTraffic()
    {
        var list = new List<DetectionEvent>();
        var sites = new[] { "142.250.1.1", "151.101.1.1", "104.16.1.1", "13.107.1.1", "52.84.1.1", "185.199.1.1" };
        for (var c = 0; c < 10; c++)
        {
            for (var i = 0; i < 40; i++)
            {
                var port = i % 5 == 0 ? 53 : i % 3 == 0 ? 80 : 443;
                list.Add(Fw($"10.0.0.{10 + c}", c + i * 15, dst: port == 53 ? "10.0.0.2" : sites[(c + i) % sites.Length], port: port,
                    ruleName: "allow-outbound"));
            }
        }
        for (var i = 0; i < 3; i++) // admin: three SSH sessions in 10 minutes
            list.Add(Fw("10.0.0.40", 30 + i * 200, dst: "10.0.0.5", port: 22));
        list.Add(Fw("198.51.100.20", 60, dst: "10.0.0.1", port: 443, action: FirewallAction.Deny, type: "auth", message: "SSL-VPN login failed"));
        list.Add(Fw("198.51.100.20", 75, dst: "10.0.0.1", port: 443, action: FirewallAction.Allow, type: "auth", message: "SSL-VPN login succeeded"));
        for (var i = 0; i < 30; i++) // internet background noise: a blocked packet every 20 s from different hosts
            list.Add(Fw($"192.0.2.{i + 1}", i * 20, dst: "10.0.0.1", port: 23 + i % 3, action: FirewallAction.Drop));
        return list;
    }

    [Fact]
    public void Default_firewall_rules_stay_quiet_on_normal_traffic()
    {
        var core = Run(Core(DbSeeder.DefaultFirewallRules().ToArray()), NormalTraffic());
        Assert.Empty(core.Hits);
    }

    public static TheoryData<string> DefaultRuleNames()
    {
        var data = new TheoryData<string>();
        foreach (var rule in DbSeeder.DefaultFirewallRules())
            data.Add(rule.Name);
        return data;
    }

    [Theory]
    [MemberData(nameof(DefaultRuleNames))]
    public void Each_default_firewall_rule_fires_on_its_attack(string name)
    {
        // "Suspicious outbound" is about inside hosts; every other attack of this test comes from outside.
        var attacker = name == "Connection to backdoor / C2 port" ? "10.0.0.66" : "203.0.113.66";
        var attack = new List<DetectionEvent>();
        switch (name)
        {
            case "Port scan": // 25 ports in 50 s, blocked
                for (var i = 0; i < 25; i++)
                    attack.Add(Fw(attacker, i * 2, port: 1000 + i, action: FirewallAction.Deny));
                break;
            case "Network sweep": // 25 hosts in 100 s
                for (var i = 0; i < 25; i++)
                    attack.Add(Fw(attacker, i * 4, dst: $"10.0.5.{i + 1}", port: 3389, action: FirewallAction.Drop));
                break;
            case "Brute force on remote-access services": // 25 SSH connections in 250 s, allowed
                for (var i = 0; i < 25; i++)
                    attack.Add(Fw(attacker, i * 10, port: 22));
                break;
            case "Flood of blocked connections": // 120 denied packets in 60 s
                for (var i = 0; i < 120; i++)
                    attack.Add(Fw(attacker, i * 0.5, port: 80, action: FirewallAction.Deny));
                break;
            case "Intrusion prevention / threat event": // three IPS events
                for (var i = 0; i < 3; i++)
                    attack.Add(Fw(attacker, i * 30, port: 445, action: FirewallAction.Deny, type: "threat",
                        message: "IPS signature matched", threat: "MS.SMB.Server.SMBv1.Buffer.Overflow"));
                break;
            case "Connection to backdoor / C2 port": // inside host -> 4444
                attack.Add(Fw(attacker, 100, dst: "198.51.100.66", port: 4444));
                break;
            case "Repeated failed logins on the firewall / VPN": // 6 refused VPN logins in 200 s
                for (var i = 0; i < 6; i++)
                    attack.Add(Fw(attacker, i * 40, dst: "10.0.0.1", port: 443, action: FirewallAction.Deny, type: "auth",
                        message: "SSL-VPN login failed"));
                break;
            default:
                throw new InvalidOperationException("No attack stream for " + name);
        }

        var core = Run(Core(Default(name)), NormalTraffic().Concat(attack));
        var hit = Assert.Single(core.Hits);
        Assert.Equal(attacker, hit.Ip);
        Assert.Subset(attack.Select(e => e.Id).ToHashSet(), hit.EventIds);
    }

    [Theory]
    [InlineData(4, FirewallAction.Deny, "auth", false)]   // one short
    [InlineData(5, FirewallAction.Deny, "auth", true)]
    [InlineData(5, FirewallAction.Reject, "AUTH", true)]  // pattern is case-insensitive
    [InlineData(8, FirewallAction.Allow, "auth", false)]  // successful logins
    [InlineData(8, FirewallAction.Deny, "traffic", false)]
    public void Failed_login_rule(int attempts, FirewallAction action, string type, bool fires)
    {
        var core = Core(Default("Repeated failed logins on the firewall / VPN"));
        for (var i = 0; i < attempts; i++)
            core.Process(Fw("198.51.100.7", i * 50, dst: "10.0.0.1", action: action, type: type, message: "login"));
        Assert.Equal(fires, core.Hits.Count == 1);
    }

    [Fact]
    public void Failed_logins_spread_over_more_than_five_minutes_do_not_fire()
    {
        var core = Core(Default("Repeated failed logins on the firewall / VPN"));
        for (var i = 0; i < 10; i++)
            core.Process(Fw("198.51.100.7", i * 100, action: FirewallAction.Deny, type: "auth")); // 4 per 300 s
        Assert.Empty(core.Hits);
    }

    [Fact]
    public void Firewall_rules_do_not_change_web_detection()
    {
        // Web events have no firewall fields: firewall rules ignore them and web rules give the same evidence.
        var web = new List<DetectionEvent>();
        for (var i = 0; i < 300; i++)
        {
            var ip = "198.51.100." + (i % 7);
            var url = (i % 9) switch
            {
                0 => "/products?id=1%27%20OR%20%271%27%3D%271",
                1 => "/download?file=../../etc/passwd",
                2 => "/wp-login.php",
                3 => "/missing" + i,
                _ => "/index.html"
            };
            web.Add(new DetectionEvent(i + 1, ip, T0.AddSeconds(i / 3.0), i % 9 == 2 ? "POST" : "GET", url,
                i % 9 == 3 ? 404 : 200, i % 11 == 0 ? "sqlmap/1.7" : "Mozilla/5.0", null));
        }

        var webOnly = Run(Core(DbSeeder.DefaultRules().ToArray()), web);
        var mixed = Run(Core(DbSeeder.DefaultRules().Concat(DbSeeder.DefaultFirewallRules()).ToArray()), web);

        static string Key(DetectionCore c) => string.Join("|", c.Hits.OrderBy(h => h.RuleId).ThenBy(h => h.Ip)
            .Select(h => $"{h.RuleId}:{h.Ip}:{string.Join(",", h.EventIds.Order())}"));
        Assert.NotEmpty(webOnly.Hits);
        Assert.Equal(Key(webOnly), Key(mixed));
    }

    // ------------------------------------------------------------------ Validator and form

    [Theory]
    [InlineData(LogSource.WebAccess, RuleKind.DistinctCount, RuleField.DestinationPort, 5, 60, "only run on firewall logs")]
    [InlineData(LogSource.Firewall, RuleKind.DistinctCount, RuleField.DestinationPort, 1, 60, "at least 2")]
    [InlineData(LogSource.Firewall, RuleKind.DistinctCount, RuleField.DestinationPort, 5, null, "time window")]
    [InlineData(LogSource.Firewall, RuleKind.DistinctCount, RuleField.UserAgent, 5, 60, "A firewall rule can inspect")]
    [InlineData(LogSource.Firewall, RuleKind.Anomaly, RuleField.Message, 20, null, "only run on web access logs")]
    public void Validator_rejects_invalid_firewall_rules(LogSource source, RuleKind kind, RuleField field, int? threshold,
        int? window, string expected)
    {
        var rule = Rule(kind, field, threshold: threshold, window: window);
        rule.AppliesTo = source;
        rule.ScoreThreshold = kind == RuleKind.Anomaly ? 0.6 : null;
        Assert.Contains(RuleValidator.Validate(rule), e => e.Contains(expected));
    }

    [Fact]
    public void Validator_checks_fields_and_filters_per_log_kind()
    {
        var fwSignature = Rule(RuleKind.Signature, RuleField.Url, "x");
        Assert.Contains(RuleValidator.Validate(fwSignature), e => e.Contains("A firewall rule can inspect"));

        var webSignature = new DetectionRule { Kind = RuleKind.Signature, Field = RuleField.ThreatName, Pattern = "x" };
        Assert.Contains(RuleValidator.Validate(webSignature), e => e.Contains("A web rule can inspect"));

        var webWithPorts = new DetectionRule { Kind = RuleKind.Threshold, Threshold = 5, WindowSeconds = 60, PortFilter = "22" };
        Assert.Contains(RuleValidator.Validate(webWithPorts), e => e.Contains("only apply to firewall rules"));

        var fwWithStatus = Rule(RuleKind.Threshold, threshold: 5, window: 60);
        fwWithStatus.StatusFilter = 404;
        Assert.Contains(RuleValidator.Validate(fwWithStatus), e => e.Contains("only apply to web rules"));

        var badPorts = Rule(RuleKind.Threshold, threshold: 5, window: 60, ports: "22-21");
        Assert.Contains(RuleValidator.Validate(badPorts), e => e.Contains("Port filter"));

        // The field of a firewall threshold rule without a pattern is not used, so any value is accepted.
        var fwThreshold = Rule(RuleKind.Threshold, RuleField.Url, threshold: 5, window: 60, actions: "Deny");
        Assert.Empty(RuleValidator.Validate(fwThreshold));
        // With a pattern the field matters.
        fwThreshold.Pattern = "^auth$";
        Assert.NotEmpty(RuleValidator.Validate(fwThreshold));
        fwThreshold.Field = RuleField.EventType;
        Assert.Empty(RuleValidator.Validate(fwThreshold));
    }

    [Fact]
    public void Validator_keeps_the_redos_probe_for_backtracking_firewall_patterns()
    {
        var rule = Rule(RuleKind.Signature, RuleField.Message, @"^(a+)+\1$");
        Assert.Contains(RuleValidator.Validate(rule), e => e.Contains("backtracking"));
    }

    [Fact]
    public void Form_normalizes_a_firewall_rule()
    {
        var model = new RuleFormModel
        {
            Name = " Auth ",
            AppliesTo = LogSource.Firewall,
            Kind = RuleKind.Threshold,
            Field = RuleField.EventType,
            Pattern = "^auth$",
            Threshold = 5,
            WindowSeconds = 300,
            MethodFilter = "post",
            StatusFilter = 404,
            PathPattern = "login",
            Actions = [FirewallAction.Reject, FirewallAction.Deny, FirewallAction.Deny],
            PortFilter = " 22, 3389 ,5900-5902 ",
            ScoreThreshold = 0.7
        };
        model.Normalize();
        var rule = model.ToRule();

        Assert.Equal("Auth", rule.Name);
        Assert.Equal("Deny,Reject", rule.ActionFilter);
        Assert.Equal("22,3389,5900-5902", rule.PortFilter);
        Assert.Equal("^auth$", rule.Pattern);
        Assert.Null(rule.MethodFilter);
        Assert.Null(rule.StatusFilter);
        Assert.Null(rule.PathPattern);
        Assert.Null(rule.ScoreThreshold);
        Assert.Empty(RuleValidator.Validate(rule));

        var back = RuleFormModel.From(rule);
        Assert.Equal(new[] { FirewallAction.Deny, FirewallAction.Reject }, back.Actions);
    }

    [Fact]
    public void Form_clears_firewall_filters_on_web_rules_and_resets_unused_fields()
    {
        var model = new RuleFormModel
        {
            Name = "web",
            AppliesTo = LogSource.WebAccess,
            Kind = RuleKind.Threshold,
            Field = RuleField.ThreatName, // not used by a web threshold rule
            Pattern = "x",
            Threshold = 20,
            WindowSeconds = 60,
            Actions = [FirewallAction.Deny],
            PortFilter = "22"
        };
        model.Normalize();
        var rule = model.ToRule();
        Assert.Null(rule.ActionFilter);
        Assert.Null(rule.PortFilter);
        Assert.Null(rule.Pattern);
        Assert.Equal(RuleField.Url, rule.Field);
        Assert.Empty(RuleValidator.Validate(rule));

        var distinct = new RuleFormModel
        {
            Name = "scan", AppliesTo = LogSource.Firewall, Kind = RuleKind.DistinctCount, Field = RuleField.DestinationPort,
            Threshold = 15, WindowSeconds = 60, PortFilter = "bad"
        };
        distinct.Normalize();
        Assert.Equal("bad", distinct.PortFilter); // kept so the validator can explain it
        Assert.Contains(RuleValidator.Validate(distinct.ToRule()), e => e.Contains("Port filter"));
    }

    [Fact]
    public void Evaluation_maps_firewall_labels()
    {
        var labels = new Dictionary<int, string> { [1] = "portscan", [2] = "normal", [3] = "c2" };
        var flagged = new Dictionary<int, HashSet<AttackType>> { [1] = [AttackType.PortScan] };
        var result = EvaluationService.Compute(labels, [1, 2, 3], flagged, [1], []);
        Assert.Equal(1, result.Overall.TP);
        Assert.Equal(1, result.Overall.FN);
        Assert.Equal(1, result.PerAttackType.Single(m => m.Name == nameof(AttackType.PortScan)).TP);
        Assert.Equal(1, result.PerAttackType.Single(m => m.Name == nameof(AttackType.SuspiciousOutbound)).FN);
    }
}
