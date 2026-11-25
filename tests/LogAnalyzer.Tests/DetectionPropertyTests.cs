using System.Reflection;
using LogAnalyzer.Web.Controllers;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Tests;

/// <summary>
/// Random event streams compared with simple reference implementations (firewall windows, unchanged web detection),
/// plus default-rule upgrades, alert texts, evaluation of firewall files and the rule form.
/// </summary>
public class DetectionPropertyTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 8, 0, 0, TimeSpan.Zero);

    private static List<CompiledRule> Compile(params DetectionRule[] rules) =>
        rules.Select((r, i) =>
        {
            r.Id = i + 1;
            return DetectionCore.TryCompile(r, out var error) ?? throw new InvalidOperationException(error);
        }).ToList();

    private static string Key(IEnumerable<RuleHit> hits) => string.Join("|", hits.OrderBy(h => h.RuleId).ThenBy(h => h.Ip, StringComparer.Ordinal)
        .Select(h => $"{h.RuleId}:{h.Ip}:{h.First:O}:{h.Last:O}:{string.Join(",", h.EventIds.Order())}"));

    private static DetectionRule FwRule(RuleKind kind, RuleField field, int threshold, int window, AttackType type = AttackType.BlockedTraffic) => new()
    {
        Name = "r", AppliesTo = LogSource.Firewall, Kind = kind, Field = field, Threshold = threshold, WindowSeconds = window, AttackType = type
    };

    // ------------------------------------------------------------------ Firewall windows

    /// <summary>Events in time order (many equal time stamps and gaps of exactly one window), few sources / hosts / ports.</summary>
    private static List<DetectionEvent> RandomFirewallEvents(int seed, int count)
    {
        var rnd = new Random(seed);
        var t = T0;
        var list = new List<DetectionEvent>();
        for (var i = 1; i <= count; i++)
        {
            t = rnd.Next(10) switch { < 4 => t, 9 => t.AddSeconds(rnd.Next(2) == 0 ? 10 : 60), _ => t.AddSeconds(rnd.Next(1, 4)) };
            list.Add(new DetectionEvent(i, "203.0.113." + rnd.Next(4), t, "DENY", "m", 0, null, null)
            {
                DestinationIp = rnd.Next(8) == 0 ? null : "10.0.0." + rnd.Next(5),
                DestinationPort = rnd.Next(8) == 0 ? null : 1 + rnd.Next(8),
                SourcePort = rnd.Next(5) == 0 ? null : 40000 + rnd.Next(6),
                Action = FirewallAction.Deny
            });
        }
        return list;
    }

    /// <summary>The definition, in quadratic time: whenever the window holds enough different values, all its events are evidence.</summary>
    private static string Reference(IEnumerable<DetectionEvent> events, DetectionRule rule, Func<DetectionEvent, string?> target,
        Func<DetectionEvent, string?> counted, bool skipWithoutValue)
    {
        var hits = new Dictionary<string, RuleHit>();
        var seen = new Dictionary<(string, string), List<DetectionEvent>>();
        foreach (var e in events)
        {
            if (skipWithoutValue && counted(e) is null)
                continue;
            var key = (e.ClientIp, target(e) ?? "");
            if (!seen.TryGetValue(key, out var all))
                seen[key] = all = [];
            all.Add(e);
            var window = all.Where(x => x.Timestamp >= e.Timestamp.AddSeconds(-rule.WindowSeconds!.Value)).ToList();
            if (window.Select(x => counted(x) ?? "#" + x.Id).Distinct().Count() < rule.Threshold)
                continue;
            if (!hits.TryGetValue(e.ClientIp, out var hit))
                hits[e.ClientIp] = hit = new RuleHit(rule.Id, e.ClientIp);
            foreach (var x in window)
                hit.Add(x.Id, x.Timestamp);
        }
        return Key(hits.Values);
    }

    [Fact]
    public void Firewall_windows_give_exactly_the_evidence_of_the_definition_also_when_idle_windows_are_removed()
    {
        var fired = 0;
        for (var seed = 0; seed < 150; seed++)
        {
            var rnd = new Random(1000 + seed);
            var events = RandomFirewallEvents(seed, 300);
            int threshold = rnd.Next(2, 6), seconds = rnd.Next(3) switch { 0 => 10, 1 => 60, _ => rnd.Next(1, 30) };

            var ports = FwRule(RuleKind.DistinctCount, RuleField.DestinationPort, threshold, seconds, AttackType.PortScan);
            var hosts = FwRule(RuleKind.DistinctCount, RuleField.DestinationIp, Math.Min(threshold, 4), seconds, AttackType.NetworkSweep);
            var flood = FwRule(RuleKind.Threshold, RuleField.Message, threshold, seconds);
            var brute = FwRule(RuleKind.Threshold, RuleField.Message, threshold, seconds, AttackType.BruteForce);

            foreach (var (rule, target, counted, skip) in new (DetectionRule, Func<DetectionEvent, string?>, Func<DetectionEvent, string?>, bool)[]
            {
                (ports, e => e.DestinationIp, e => e.DestinationPort?.ToString(), true),
                (hosts, _ => null, e => e.DestinationIp, true),
                (flood, _ => null, _ => null, false),
                (brute, e => e.DestinationIp, e => e.SourcePort?.ToString(), false)
            })
            {
                foreach (var limit in new[] { 1, 3, 10_000 })
                {
                    var core = new DetectionCore(Compile(rule), limit);
                    events.ForEach(core.Process);
                    Assert.Equal(Reference(events, rule, target, counted, skip), Key(core.Hits));
                    fired += core.Hits.Count;
                }
            }
        }
        Assert.True(fired > 1000, $"only {fired} hits: the streams test nothing");
    }

    [Theory]
    [InlineData(60, true)]    // exactly WindowSeconds old: still inside
    [InlineData(61, false)]
    public void Window_boundary_is_inclusive(int seconds, bool fires)
    {
        var core = new DetectionCore(Compile(FwRule(RuleKind.DistinctCount, RuleField.DestinationPort, 2, 60)));
        core.Process(new DetectionEvent(1, "203.0.113.1", T0, "DENY", "m", 0, null, null) { DestinationIp = "10.0.0.5", DestinationPort = 1 });
        core.Process(new DetectionEvent(2, "203.0.113.1", T0.AddSeconds(seconds), "DENY", "m", 0, null, null) { DestinationIp = "10.0.0.5", DestinationPort = 2 });
        Assert.Equal(fires, core.Hits.Count == 1);
    }

    [Fact]
    public void Idle_windows_are_removed_so_memory_does_not_grow_with_the_number_of_sources()
    {
        // 300,000 different (spoofed) sources over 25 hours: every rule used to keep a window per source for the whole run.
        var core = new DetectionCore(Compile(DbSeeder.DefaultFirewallRules().ToArray()));
        for (var i = 0; i < 300_000; i++)
            core.Process(new DetectionEvent(i + 1, $"203.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}", T0.AddMilliseconds(i * 300), "DENY", "m", 0, null, null)
            {
                DestinationIp = "10.0.0." + i % 50, DestinationPort = i % 3 == 0 ? 22 : 8080, SourcePort = 40000, Action = FirewallAction.Deny
            });
        Assert.InRange(core.OpenFirewallWindows, 1, 60_000);
        Assert.Empty(core.Hits);
    }

    [Fact]
    public void Replies_are_remembered_for_a_limited_time_only()
    {
        // The target used a service of 203.0.113.5:443 an hour before that host scans it from port 443.
        var core = new DetectionCore(Compile(DbSeeder.DefaultFirewallRules().Where(r => r.Name == "Port scan").ToArray()));
        core.Process(new DetectionEvent(1, "10.0.0.5", T0, "ALLOW", "m", 0, null, null)
            { DestinationIp = "203.0.113.5", DestinationPort = 443, SourcePort = 50000, Action = FirewallAction.Allow });
        for (var i = 0; i < 4; i++) // other traffic lets the time pass
            core.Process(new DetectionEvent(2 + i, "10.0.0.6", T0.AddMinutes(16 * (i + 1)), "ALLOW", "m", 0, null, null)
                { DestinationIp = "198.51.100.1", DestinationPort = 443, SourcePort = 50000 + i, Action = FirewallAction.Allow });
        for (var i = 0; i < 20; i++)
            core.Process(new DetectionEvent(10 + i, "203.0.113.5", T0.AddMinutes(65).AddSeconds(i), "DROP", "m", 0, null, null)
                { DestinationIp = "10.0.0.5", DestinationPort = 2000 + i, SourcePort = 443, Action = FirewallAction.Drop });
        Assert.Equal(20, Assert.Single(core.Hits).EventIds.Count);
    }

    // ------------------------------------------------------------------ Web detection is unchanged

    /// <summary>
    /// Matching loop of DetectionCore as of commit 8356719 (before firewall logs), kept as the reference for web rules.
    /// Regex timeouts are left out: the default rules use the linear engine and cannot time out.
    /// </summary>
    private sealed class OldWebCore(IReadOnlyList<CompiledRule> rules)
    {
        private readonly Dictionary<(int, string), RuleHit> _hits = [];
        private readonly Dictionary<(int, string), List<(DateTimeOffset Ts, long Id)>> _windows = [];
        public IEnumerable<RuleHit> Hits => _hits.Values;

        public void Process(DetectionEvent e)
        {
            var url = UrlDecoder.Decode(e.Url);
            foreach (var r in rules)
            {
                if (r.Rule.Kind == RuleKind.Signature)
                {
                    var value = r.Rule.Field switch
                    {
                        RuleField.UserAgent => e.UserAgent ?? string.Empty,
                        RuleField.Referrer => UrlDecoder.Decode(e.Referrer),
                        _ => url
                    };
                    if (r.Pattern is not null && DetectionCore.Match(r.Pattern, value) != MatchOutcome.NoMatch)
                        Hit(r, e).Add(e.Id, e.Timestamp);
                }
                else if (r.Rule.Kind == RuleKind.Threshold
                         && (r.Rule.MethodFilter is null || string.Equals(r.Rule.MethodFilter, e.Method, StringComparison.OrdinalIgnoreCase))
                         && (r.Rule.StatusFilter is null || r.Rule.StatusFilter == e.StatusCode)
                         && (r.PathPattern is null || DetectionCore.Match(r.PathPattern, url) != MatchOutcome.NoMatch))
                {
                    if (!_windows.TryGetValue((r.Rule.Id, e.ClientIp), out var w))
                        _windows[(r.Rule.Id, e.ClientIp)] = w = [];
                    w.Add((e.Timestamp, e.Id));
                    while (w.Count > 1 && w[0].Ts < e.Timestamp - r.Window)
                        w.RemoveAt(0);
                    if (w.Count >= r.Rule.Threshold)
                        foreach (var (ts, id) in w)
                            Hit(r, e).Add(id, ts);
                }
            }
        }

        private RuleHit Hit(CompiledRule r, DetectionEvent e)
        {
            if (!_hits.TryGetValue((r.Rule.Id, e.ClientIp), out var hit))
                _hits[(r.Rule.Id, e.ClientIp)] = hit = new RuleHit(r.Rule.Id, e.ClientIp);
            return hit;
        }
    }

    [Fact]
    public void Web_evidence_is_identical_to_the_implementation_before_firewall_logs()
    {
        string[] urls =
        [
            "/", "/index.php?id=1", "/login", "/wp-login.php", "/p?id=1%27%20OR%20%271%27%3D%271", "/p?id=1+union+select+2", "/a%252e%252e%252fetc/passwd",
            "/x?q=%3Cscript%3Ealert(1)%3C/script%3E", "/missing", "/q?s=100%", "/auth?next=%2Fhome", "", "/é?x=%C3%A9", "/a+b?c=--"
        ];
        string?[] agents = ["Mozilla/5.0", "sqlmap/1.8", "Nikto", null, ""];
        string?[] referrers = [null, "https://example.com/", "https://x/%3Cscript", ""];
        var totalHits = 0;
        for (var seed = 0; seed < 60; seed++)
        {
            var rnd = new Random(seed);
            var rules = DbSeeder.DefaultRules().ToList();
            rules.Add(new DetectionRule { Name = "ref", Kind = RuleKind.Signature, Field = RuleField.Referrer, Pattern = "(?i)<script" });
            rules.Add(new DetectionRule { Name = "any", Kind = RuleKind.Threshold, Threshold = 5, WindowSeconds = 10, PathPattern = "^/p" });
            rules.Add(new DetectionRule { Name = "default window", Kind = RuleKind.Threshold, Threshold = 8, MethodFilter = "get" });
            var webRules = rules.ToArray();
            // Firewall rules in the same list must not change anything either.
            var all = seed % 2 == 0 ? webRules : webRules.Concat(DbSeeder.DefaultFirewallRules()).ToArray();

            var t = T0;
            var events = new List<DetectionEvent>();
            for (var i = 1; i <= 800; i++)
            {
                t = rnd.Next(4) == 0 ? t.AddSeconds(rnd.Next(0, 12)) : t;
                events.Add(new DetectionEvent(i, rnd.Next(30) == 0 ? "-" : "198.51.100." + rnd.Next(5), t, rnd.Next(3) == 0 ? "POST" : "GET",
                    urls[rnd.Next(urls.Length)], rnd.Next(3) == 0 ? 404 : 200, agents[rnd.Next(agents.Length)], referrers[rnd.Next(referrers.Length)], 10));
            }

            var compiled = Compile(all);
            var now = new DetectionCore(compiled);
            var old = new OldWebCore(compiled.Where(c => !c.IsFirewall).ToList());
            foreach (var e in events)
            {
                now.Process(e);
                old.Process(e);
            }
            Assert.Equal(Key(old.Hits), Key(now.Hits));
            totalHits += now.Hits.Count;
            Assert.All(now.Hits, h => Assert.Null(h.Traffic));
            // Titles and details of web alerts are what they were.
            foreach (var h in now.Hits)
            {
                Assert.Equal($"{all[h.RuleId - 1].Name} from {h.Ip}", DetectionEngine.Title(all[h.RuleId - 1], h));
                Assert.Null(DetectionEngine.Describe(h));
            }
        }
        Assert.True(totalHits > 500, $"{totalHits} hits");
    }

    // ------------------------------------------------------------------ Default rules: seeding and upgrade

    private static string Settings(DetectionRule r) =>
        string.Join("|", r.Name, r.Description, r.AttackType, r.Severity, r.Kind, r.Field, r.Pattern, r.Threshold, r.WindowSeconds, r.MethodFilter,
            r.PathPattern, r.StatusFilter, r.AppliesTo, r.ActionFilter, r.PortFilter, r.ScoreThreshold);

    [Fact]
    public void Untouched_old_default_rules_are_upgraded_and_keep_their_id_and_switch()
    {
        var existing = DbSeeder.SupersededFirewallRules().ToList();
        Assert.Equal(5, existing.Count);
        for (var i = 0; i < existing.Count; i++)
        {
            existing[i].Id = 40 + i;
            existing[i].IsEnabled = i % 2 == 0;
            existing[i].CreatedAt = new DateTime(2026, 11, 21);
        }

        var upgraded = DbSeeder.UpgradeUntouchedDefaults(existing);

        Assert.Equal(5, upgraded.Count);
        for (var i = 0; i < existing.Count; i++)
        {
            Assert.Equal(Settings(DbSeeder.DefaultFirewallRules().Single(r => r.Name == existing[i].Name)), Settings(existing[i]));
            Assert.Equal(40 + i, existing[i].Id);
            Assert.Equal(i % 2 == 0, existing[i].IsEnabled);
            Assert.Equal(new DateTime(2026, 11, 21), existing[i].CreatedAt);
        }
        Assert.Empty(DbSeeder.UpgradeUntouchedDefaults(existing)); // second start: nothing to do
        Assert.Empty(DbSeeder.UpgradeUntouchedDefaults(DbSeeder.DefaultFirewallRules())); // new database
    }

    public static TheoryData<string, string> Edits()
    {
        var data = new TheoryData<string, string>();
        foreach (var rule in DbSeeder.SupersededFirewallRules())
            foreach (var edit in new[] { "name", "description", "type", "severity", "field", "pattern", "threshold", "window", "actions", "ports", "path", "kind" })
                data.Add(rule.Name, edit);
        return data;
    }

    [Theory]
    [MemberData(nameof(Edits))]
    public void A_default_rule_an_admin_changed_is_never_touched(string name, string edit)
    {
        var rule = DbSeeder.SupersededFirewallRules().Single(r => r.Name == name);
        switch (edit)
        {
            case "name": rule.Name += " (ours)"; break;
            case "description": rule.Description = "ours"; break;
            case "type": rule.AttackType = AttackType.Intrusion; break;
            case "severity": rule.Severity = Severity.Low; break;
            case "field": rule.Field = RuleField.RuleName; break;
            case "pattern": rule.Pattern = "^x$"; break;
            case "threshold": rule.Threshold++; break;
            case "window": rule.WindowSeconds++; break;
            case "actions": rule.ActionFilter = "Allow"; break;
            case "ports": rule.PortFilter = "22"; break;
            case "path": rule.PathPattern = "x"; break;
            case "kind": rule.Kind = RuleKind.Signature; break;
        }
        var before = Settings(rule);
        Assert.Empty(DbSeeder.UpgradeUntouchedDefaults([rule]));
        Assert.Equal(before, Settings(rule));
    }

    [Fact]
    public void Superseded_rules_are_the_ones_seeded_on_2026_11_21()
    {
        // Fingerprints of the old values that matter for detection (the descriptions are compared word for word in the code).
        var old = DbSeeder.SupersededFirewallRules().ToDictionary(r => r.Name);
        Assert.Null(old["Network sweep"].ActionFilter);
        Assert.StartsWith("One source contacts 20 or more different destination hosts within 2 minutes", old["Network sweep"].Description);
        Assert.Equal("Deny,Reject", old["Repeated failed logins on the firewall / VPN"].ActionFilter);
        Assert.StartsWith("One source tries 15 or more different destination ports within 60 seconds", old["Port scan"].Description);
        Assert.StartsWith("A connection to a port typical for backdoors", old["Connection to backdoor / C2 port"].Description);
        Assert.All(old.Values, r => Assert.True(r.Description!.Length <= 1000));
    }

    [Fact]
    public void Seeding_web_rules_skips_names_that_are_already_taken()
    {
        // An admin turned a default web rule into a firewall rule and deleted the others: at the next start there is no
        // web rule, and seeding its (unique) name again made the application fail to start.
        var rules = DbSeeder.RulesToSeed(DbSeeder.DefaultRules(), ["sql INJECTION signatures", "Port scan"]);
        Assert.Equal(5, rules.Count);
        Assert.DoesNotContain(rules, r => r.Name == "SQL injection signatures");
    }

    // ------------------------------------------------------------------ Alert texts

    private static DetectionEvent Event(long id, double seconds, string? dst, int? port, FirewallAction? action, string src = "203.0.113.5", string? threat = null) =>
        new(id, src, T0.AddSeconds(seconds), "X", "m", 0, null, null)
        { DestinationIp = dst, DestinationPort = port, SourcePort = 40000 + (int)id, Action = action, ThreatName = threat, EventType = "traffic" };

    private static RuleHit HitOf(string rule, IEnumerable<DetectionEvent> events)
    {
        var core = new DetectionCore(Compile(DbSeeder.DefaultFirewallRules().Single(r => r.Name == rule)));
        foreach (var e in events)
            core.Process(e);
        return Assert.Single(core.Hits);
    }

    [Fact]
    public void Port_scan_alert_says_how_many_ports_on_which_host()
    {
        var hit = HitOf("Port scan", Enumerable.Range(0, 24).Select(i => Event(i + 1, i * 2, "10.0.0.5", 20 + i, i == 2 ? FirewallAction.Allow : FirewallAction.Deny)));
        Assert.Equal("24 events between 2026-11-21 08:00:00 and 08:00:46: 24 different destination ports (20-43) on 1 host (10.0.0.5); " +
                     "1 allowed, 23 blocked.", DetectionEngine.Describe(hit));
    }

    [Fact]
    public void Sweep_threat_and_c2_alerts_describe_their_evidence()
    {
        var sweep = HitOf("Network sweep", Enumerable.Range(0, 25).Select(i => Event(i + 1, i, "10.0.3." + i, 445, FirewallAction.Drop)));
        Assert.Equal("25 events between 2026-11-21 08:00:00 and 08:00:24: destination port 445 on 25 different hosts; 25 blocked.", DetectionEngine.Describe(sweep));

        var threat = HitOf("Intrusion prevention / threat event",
        [
            Event(1, 0, "10.0.0.5", 80, FirewallAction.Alert, threat: "SQL injection"), Event(2, 5, "10.0.0.5", 80, FirewallAction.Drop, threat: "SQL injection"),
            Event(3, 86400, "10.0.0.5", 80, null, threat: new string('x', 200))
        ]);
        Assert.Equal("3 events between 2026-11-21 08:00:00 and 2026-11-22 08:00:00: destination port 80 on 1 host (10.0.0.5); 1 blocked, " +
                     "1 detected, not blocked, 1 without a decision. Threats: SQL injection, " + new string('x', 80) + "....", DetectionEngine.Describe(threat));

        var c2 = HitOf("Connection to backdoor / C2 port", [Event(1, 0, "198.51.100.200", 4444, FirewallAction.Allow, "10.0.0.23")]);
        Assert.Equal("1 event at 2026-11-21 08:00:00: destination port 4444 on 1 host (198.51.100.200); 1 allowed.", DetectionEngine.Describe(c2));
    }

    [Fact]
    public void Huge_alerts_keep_a_bounded_summary_that_fits_the_column()
    {
        var hit = HitOf("Port scan", Enumerable.Range(0, 60_000).Select(i => Event(i + 1, i * 0.001, "10.0.0.5", 1 + i, FirewallAction.Drop)));
        Assert.Equal("60,000 events between 2026-11-21 08:00:00 and 08:00:59: more than 1,000 different destination ports on 1 host (10.0.0.5); 60,000 blocked.",
            DetectionEngine.Describe(hit));
        var many = HitOf("Intrusion prevention / threat event",
            Enumerable.Range(0, 3000).Select(i => Event(i + 1, i, "2001:db8::" + i, i, FirewallAction.Alert, threat: new string((char)('a' + i % 26), 500))));
        Assert.True(DetectionEngine.Describe(many)!.Length <= 1000);
    }

    [Fact]
    public void Threat_without_a_source_address_is_one_alert_that_says_so()
    {
        var events = new[] { Event(1, 0, "10.0.0.5", null, FirewallAction.Alert, "-", "host is targeted"), Event(2, 1, "10.0.0.6", null, FirewallAction.Alert, "-", "host is targeted") };
        var hit = HitOf("Intrusion prevention / threat event", events);
        Assert.Equal(2, hit.EventIds.Count); // not lost
        var rule = DbSeeder.DefaultFirewallRules().Single(r => r.Name.StartsWith("Intrusion"));
        Assert.Equal("Intrusion prevention / threat event (source address not logged)", DetectionEngine.Title(rule, hit));
        Assert.Equal("Intrusion prevention / threat event from 10.0.0.9", DetectionEngine.Title(rule, new RuleHit(1, "10.0.0.9")));
    }

    [Fact]
    public void Capped_firewall_hits_keep_all_evidence_and_the_merged_one_has_no_summary()
    {
        var core = new DetectionCore(Compile(DbSeeder.DefaultFirewallRules().Single(r => r.Name.StartsWith("Intrusion"))));
        for (var i = 0; i < 50; i++)
            core.Process(Event(i + 1, i, "10.0.0.5", 80, FirewallAction.Drop, "203.0.113." + i, "x"));
        var capped = DetectionCore.CapPerRule(core.Hits, 10);
        Assert.Equal(11, capped.Count);
        Assert.Equal(50, capped.SelectMany(h => h.EventIds).Distinct().Count());
        Assert.Null(capped[^1].Traffic);
        Assert.StartsWith("The rule matched more than", DetectionEngine.Describe(capped[^1]));
    }

    // ------------------------------------------------------------------ Evaluation of firewall files

    [Fact]
    public void Firewall_evaluation_has_no_anomaly_rows_and_separates_false_alarms_from_overlaps()
    {
        var labels = new Dictionary<int, string> { [1] = "portscan", [2] = "normal", [3] = "normal", [4] = "sweep" };
        var flagged = new Dictionary<int, HashSet<AttackType>>
        {
            [1] = [AttackType.PortScan, AttackType.BlockedTraffic],
            [2] = [AttackType.BlockedTraffic],
            [4] = [AttackType.NetworkSweep]
        };
        var fw = EvaluationService.Compute(labels, [1, 2, 3, 4], flagged, [1, 2, 4], [], LogSource.Firewall);

        var row = Assert.Single(fw.Comparison);
        Assert.Contains("Firewall rules", row.Name);
        Assert.Equal((2, 1, 0, 1), (row.TP, row.FP, row.FN, row.TN));
        var blocked = fw.PerAttackType.Single(m => m.Name == nameof(AttackType.BlockedTraffic));
        Assert.Equal(2, blocked.FP); // unchanged definition: any line that is not labelled as this type
        Assert.Equal(1, fw.FalsePositivesOnNormalLines[nameof(AttackType.BlockedTraffic)]); // one of them is a real false alarm
        Assert.Equal(0, fw.FalsePositivesOnNormalLines[nameof(AttackType.PortScan)]);

        var web = EvaluationService.Compute(labels, [1, 2, 3, 4], flagged, [1, 2, 4], []);
        Assert.Equal(3, web.Comparison.Count);
        Assert.Equal("Rules only (signature + threshold)", web.Comparison[0].Name);
        Assert.Equal(fw.Overall, web.Overall);
    }

    [Fact]
    public void Every_label_of_the_evaluation_is_documented()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "docs", "evaluation-guide.md")))
            dir = dir.Parent;
        var guide = File.ReadAllText(Path.Combine(dir!.FullName, "docs", "evaluation-guide.md"));
        Assert.All(EvaluationService.LabelMap.Keys, label => Assert.Contains("`" + label + "`", guide));
    }

    // ------------------------------------------------------------------ Rule form and tester

    [Fact]
    public void Opening_and_saving_a_default_rule_changes_nothing()
    {
        foreach (var rule in DbSeeder.DefaultFirewallRules().Concat(DbSeeder.DefaultRules()))
        {
            var model = RuleFormModel.From(rule);
            model.Normalize();
            Assert.Equal(Settings(rule), Settings(model.ToRule()));
        }
    }

    [Fact]
    public void Turning_a_web_rule_into_a_firewall_rule_leaves_no_http_filters_behind()
    {
        var existing = DbSeeder.DefaultRules().Single(r => r.Name == "Login brute force");
        var model = RuleFormModel.From(existing);
        model.AppliesTo = LogSource.Firewall;
        model.PortFilter = "22";
        model.Normalize();
        model.ApplyTo(existing);
        Assert.Null(existing.MethodFilter);
        Assert.Null(existing.PathPattern);
        Assert.Null(existing.StatusFilter);
        Assert.Equal(RuleField.Message, existing.Field);
        Assert.Empty(RuleValidator.Validate(existing));
    }

    [Theory]
    [InlineData("22 , 3389 ,, 5900 - 5902 ,", "22,3389,5900-5902", 5)]
    [InlineData("1-100,50-150,100", "1-100,50-150,100", 150)] // overlapping ranges count once
    [InlineData("0-65535", "0-65535", 65536)]
    [InlineData("00022", "22", 1)]
    public void Port_filters_are_canonical_and_never_longer_than_typed(string text, string canonical, int count)
    {
        Assert.True(PortSet.TryParse(text, out var set, out _));
        Assert.Equal(canonical, set!.ToString());
        Assert.Equal(count, set.Count);
        Assert.True(canonical.Length <= text.Length);
    }

    [Theory]
    [InlineData("２２")]      // full-width digits
    [InlineData("٢٢")]      // Arabic-Indic digits
    [InlineData("22–23")]   // en dash
    [InlineData("22;23")]
    [InlineData("5-")]
    [InlineData("0x16")]
    public void Port_filters_accept_ascii_digits_and_commas_only(string text) => Assert.False(PortSet.TryParse(text, out _, out _));

    [Theory]
    [InlineData(99, 1, 3)]
    [InlineData(1, 99, 3)]
    [InlineData(1, 0, 99)]
    public void Unknown_enum_values_of_a_crafted_post_are_rejected(int appliesTo, int kind, int field)
    {
        var model = new RuleFormModel
        {
            Name = "x", AppliesTo = (LogSource)appliesTo, Kind = (RuleKind)kind, Field = (RuleField)field, Pattern = "x", Threshold = 5, WindowSeconds = 60
        };
        model.Normalize();
        Assert.NotEmpty(RuleValidator.Validate(model.ToRule()));
    }

    [Fact]
    public void Rule_changes_need_an_admin_a_post_and_the_antiforgery_token()
    {
        foreach (var name in new[] { "Save", "Toggle", "Delete" })
        {
            var action = typeof(RulesController).GetMethods(BindingFlags.Public | BindingFlags.Instance).Single(m => m.Name == name);
            Assert.NotNull(action.GetCustomAttribute<HttpPostAttribute>());
            Assert.NotNull(action.GetCustomAttribute<ValidateAntiForgeryTokenAttribute>());
            Assert.Equal(Roles.Admin, action.GetCustomAttribute<AuthorizeAttribute>()?.Roles);
        }
        foreach (var property in new[] { nameof(RuleFormModel.LogFiles), nameof(RuleFormModel.TestResult) })
            Assert.NotNull(typeof(RuleFormModel).GetProperty(property)!.GetCustomAttribute<Microsoft.AspNetCore.Mvc.ModelBinding.BindNeverAttribute>());
    }

    private static AppDbContext InMemory() =>
        new(new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase("rules-" + Guid.NewGuid()).Options);

    [Fact]
    public async Task Rule_tester_refuses_files_of_the_other_kind_and_caps_the_alert_count()
    {
        await using var db = InMemory();
        db.LogFiles.Add(new LogFile { Id = 1, FileName = "fw.log", Source = LogSource.Firewall, Status = LogFileStatus.Completed });
        db.LogFiles.Add(new LogFile { Id = 2, FileName = "web.log", Source = LogSource.WebAccess, Status = LogFileStatus.Completed });
        for (var i = 0; i < 1500; i++)
            db.LogEvents.Add(new LogEvent
            {
                LogFileId = 1, LineNumber = i + 1, ClientIp = $"10.0.{i / 250}.{i % 250}", Timestamp = T0.AddSeconds(i), Method = "ALLOW", Url = "m", RawLine = "r",
                DestinationIp = "198.51.100.1", DestinationPort = 4444, SourcePort = 50000, Action = FirewallAction.Allow
            });
        await db.SaveChangesAsync();
        var tester = new RuleTester(db, new AnomalyDetector());
        var rule = DbSeeder.DefaultFirewallRules().Single(r => r.Name.StartsWith("Connection to backdoor"));

        Assert.Contains("firewall log", Assert.Single((await tester.TestAsync(rule, 2, default)).Errors));
        Assert.Contains("does not exist", Assert.Single((await tester.TestAsync(rule, 3, default)).Errors));
        Assert.Contains("web access", Assert.Single((await tester.TestAsync(DbSeeder.DefaultRules().First(), 1, default)).Errors));

        var result = await tester.TestAsync(rule, 1, default);
        Assert.Empty(result.Errors);
        Assert.Equal(1500, result.MatchedEvents);
        Assert.Equal(DetectionEngine.MaxAlertsPerRule + 1, result.AlertsWouldBeCreated); // what detection really creates
    }

    [Fact]
    public async Task Evaluation_of_a_stored_firewall_file_uses_the_firewall_tables()
    {
        await using var db = InMemory();
        db.LogFiles.Add(new LogFile { Id = 1, FileName = "fw.log", Source = LogSource.Firewall, Status = LogFileStatus.Completed });
        db.LogEvents.Add(new LogEvent { Id = 1, LogFileId = 1, LineNumber = 1, ClientIp = "10.0.0.1", Timestamp = T0, Method = "DENY", Url = "m", RawLine = "r" });
        await db.SaveChangesAsync();
        var result = await new EvaluationService(db).EvaluateAsync(1, new Dictionary<int, string> { [1] = "normal" }, default);
        Assert.Contains("Firewall rules", Assert.Single(result.Comparison).Name);
        Assert.Equal(1, result.Overall.TN);
    }
}
