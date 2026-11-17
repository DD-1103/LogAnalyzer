using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;

namespace LogAnalyzer.Tests;

public class DetectionCoreTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
    private long _id;

    private DetectionEvent Ev(string url, string ip = "1.2.3.4", int secondsAfter = 0, string method = "GET",
        int status = 200, string? ua = "Mozilla/5.0") =>
        new(++_id, ip, T0.AddSeconds(secondsAfter), method, url, status, ua, null);

    private static DetectionCore Core(params DetectionRule[] rules) =>
        new(rules.Select((r, i) =>
        {
            r.Id = i + 1;
            return DetectionCore.TryCompile(r, out var error) ?? throw new InvalidOperationException(error);
        }).ToList());

    private static DetectionRule Default(string name) => DbSeeder.DefaultRules().Single(r => r.Name == name);

    [Theory]
    [InlineData("/products?id=1%27%20OR%20%271%27%3D%271")]
    [InlineData("/products?id=1+UNION+ALL+SELECT+username,password+FROM+users--")]
    [InlineData("/products?id=1%2527%2520or%25201%253D1")] // double encoded
    [InlineData("/search?q=1'+AND+SLEEP(5)--")]
    public void Sql_injection_rule_matches_payloads(string url)
    {
        var core = Core(Default("SQL injection signatures"));
        core.Process(Ev(url));
        Assert.Single(core.Hits);
    }

    [Theory]
    [InlineData("/search?q=o%27neill+wine")]
    [InlineData("/products?category=wine")]
    [InlineData("/blog/how-to-select-a-wine")]
    public void Sql_injection_rule_ignores_benign_urls(string url)
    {
        var core = Core(Default("SQL injection signatures"));
        core.Process(Ev(url));
        Assert.Empty(core.Hits);
    }

    [Theory]
    [InlineData("XSS signatures", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")]
    [InlineData("XSS signatures", "/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")]
    [InlineData("Path traversal / LFI", "/download?file=../../../../etc/passwd")]
    [InlineData("Path traversal / LFI", "/download?file=%252e%252e%252fetc%252fpasswd")]
    [InlineData("Path traversal / LFI", "/index.php?page=php://filter/convert.base64-encode/resource=index.php")]
    public void Signature_rules_match(string rule, string url)
    {
        var core = Core(Default(rule));
        core.Process(Ev(url));
        Assert.Single(core.Hits);
    }

    [Fact]
    public void Scanner_rule_looks_at_the_user_agent()
    {
        var core = Core(Default("Known scanner user agents"));
        core.Process(Ev("/", ua: "sqlmap/1.8.3#stable (https://sqlmap.org)"));
        core.Process(Ev("/", ua: "Mozilla/5.0 (Windows NT 10.0)"));
        core.Process(Ev("/", ua: null));
        Assert.Single(core.Hits.Single().EventIds);
    }

    [Fact]
    public void Brute_force_needs_threshold_within_window()
    {
        var core = Core(Default("Login brute force")); // >= 20 POST to login paths in 60 s
        for (var i = 0; i < 19; i++)
            core.Process(Ev("/login", method: "POST", secondsAfter: i * 2));
        Assert.Empty(core.Hits);

        core.Process(Ev("/login", method: "POST", secondsAfter: 40));
        var hit = Assert.Single(core.Hits);
        Assert.Equal(20, hit.EventIds.Count); // every event in the window is evidence
    }

    [Fact]
    public void Slow_brute_force_stays_under_the_threshold()
    {
        var core = Core(Default("Login brute force"));
        for (var i = 0; i < 100; i++)
            core.Process(Ev("/login", method: "POST", secondsAfter: i * 10)); // 6 per minute
        Assert.Empty(core.Hits);
    }

    [Fact]
    public void Threshold_filters_method_and_ip()
    {
        var core = Core(Default("Login brute force"));
        for (var i = 0; i < 30; i++)
        {
            core.Process(Ev("/login", method: "GET", secondsAfter: i));                       // wrong method
            core.Process(Ev("/login", method: "POST", ip: $"9.9.9.{i}", secondsAfter: i));    // different IPs
        }
        Assert.Empty(core.Hits);
    }

    [Fact]
    public void Directory_enumeration_counts_404s()
    {
        var core = Core(Default("Directory enumeration"));
        for (var i = 0; i < 60; i++)
            core.Process(Ev($"/word{i}", status: i % 10 == 0 ? 200 : 404, secondsAfter: i / 2));
        var hit = Assert.Single(core.Hits);
        Assert.Equal(54, hit.EventIds.Count); // only 404 responses are evidence
    }

    [Fact]
    public void One_hit_per_rule_and_ip()
    {
        var core = Core(Default("XSS signatures"));
        core.Process(Ev("/q=%3Cscript%3E", ip: "1.1.1.1"));
        core.Process(Ev("/q=%3Cscript%3E", ip: "1.1.1.1", secondsAfter: 5));
        core.Process(Ev("/q=%3Cscript%3E", ip: "2.2.2.2"));
        Assert.Equal(2, core.Hits.Count);
        var first = core.Hits.Single(h => h.Ip == "1.1.1.1");
        Assert.Equal(T0, first.First);
        Assert.Equal(T0.AddSeconds(5), first.Last);
    }

    [Fact]
    public void Invalid_or_incomplete_rules_do_not_compile()
    {
        Assert.Null(DetectionCore.TryCompile(new DetectionRule { Kind = RuleKind.Signature, Pattern = "(abc" }, out var e1));
        Assert.Contains("Invalid regular expression", e1);
        Assert.Null(DetectionCore.TryCompile(new DetectionRule { Kind = RuleKind.Signature }, out _));
        Assert.Null(DetectionCore.TryCompile(new DetectionRule { Kind = RuleKind.Threshold, Threshold = 0 }, out _));
    }
}

public class RuleValidatorTests
{
    [Fact]
    public void Rejects_catastrophic_backtracking()
    {
        // Nested quantifiers alone are safe since audit fix 04 (linear NonBacktracking engine) ...
        Assert.Empty(RuleValidator.Validate(new DetectionRule { Kind = RuleKind.Signature, Pattern = "(a+)+$" }));
        // ... but with a backreference the pattern needs the backtracking engine and is rejected.
        var errors = RuleValidator.Validate(new DetectionRule { Kind = RuleKind.Signature, Pattern = @"^(a+)+\1$" });
        Assert.Contains(errors, e => e.Contains("too slow"));
    }

    [Fact]
    public void Accepts_all_default_rules()
    {
        foreach (var rule in DbSeeder.DefaultRules())
            Assert.Empty(RuleValidator.Validate(rule));
    }

    [Fact]
    public void Anomaly_rule_needs_a_valid_score_threshold()
    {
        var rule = new DetectionRule { Kind = RuleKind.Anomaly, Threshold = 20, ScoreThreshold = 1.5 };
        Assert.NotEmpty(RuleValidator.Validate(rule));
        rule.ScoreThreshold = 0.62;
        Assert.Empty(RuleValidator.Validate(rule));
    }
}
