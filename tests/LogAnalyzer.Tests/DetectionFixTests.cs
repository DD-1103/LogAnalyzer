using System.Diagnostics;
using System.Net;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace LogAnalyzer.Tests;

/// <summary>Regression tests for audit findings 04, 03, 07, 10 and 29 (fixed 2026-11-17).</summary>
public class DetectionFixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static DetectionRule Signature(string pattern, int id = 1) => new()
    {
        Id = id, Name = "rule " + id, Kind = RuleKind.Signature, AttackType = AttackType.Xss,
        Severity = Severity.Medium, Field = RuleField.Url, Pattern = pattern
    };

    private static DetectionEvent Ev(long id, string url, string ip = "198.51.100.1") =>
        new(id, ip, T0.AddSeconds(id), "GET", url, 200, "ua", null);

    // ---- 04: regex timeouts must not hide attacks ----

    private const string WeakRule = @"(?i)<(\w+\s*)+on\w+\s*=";
    private const string EvasiveUrl = "/search?x=<aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!&q=<svg onload=alert(1)>";

    [Fact]
    public void WeakAdminRule_IsCompiledLinear_AndCatchesTheEvasivePayload()
    {
        var compiled = DetectionCore.TryCompile(Signature(WeakRule), out var error);
        Assert.NotNull(compiled);
        Assert.Null(error);
        Assert.False(compiled.Backtracking);
        Assert.Empty(RuleValidator.Validate(Signature(WeakRule)));

        var core = new DetectionCore([compiled]);
        var sw = Stopwatch.StartNew();
        core.Process(Ev(1, EvasiveUrl));
        sw.Stop();

        Assert.Single(core.Hits);
        Assert.Empty(core.Timeouts);
        Assert.True(sw.ElapsedMilliseconds < 200, $"{sw.ElapsedMilliseconds} ms");
    }

    // (a+)+ followed by a backreference: needs the backtracking engine and is exponential on "aaaa...!".
    private const string BacktrackingRule = @"^(a+)+\1$";

    [Fact]
    public void BacktrackingOnlyPattern_IsRejectedByTheValidator()
    {
        var compiled = DetectionCore.TryCompile(Signature(BacktrackingRule), out _);
        Assert.NotNull(compiled);
        Assert.True(compiled.Backtracking);
        Assert.Contains(RuleValidator.Validate(Signature(BacktrackingRule)), e => e.Contains("backtracking"));
    }

    [Fact]
    public void Timeout_IsCountedAsMatch_AndReported()
    {
        var core = new DetectionCore([DetectionCore.TryCompile(Signature(BacktrackingRule), out _)!]);
        core.Process(Ev(1, new string('a', 40) + "!"));

        var hit = Assert.Single(core.Hits);
        Assert.Equal(1, hit.TimedOutEvents);
        Assert.Equal(1, core.Timeouts[1]);
        Assert.Contains("timed out on 1 event", Assert.Single(core.Warnings(_ => "weak")));
    }

    [Fact]
    public void CircuitBreaker_SkipsARuleAfterTooManyTimeouts()
    {
        var core = new DetectionCore([DetectionCore.TryCompile(Signature(BacktrackingRule), out _)!]);
        // Simulate the breaker state without spending 50 x 250 ms: same code path as real timeouts.
        var timeouts = (Dictionary<int, int>)typeof(DetectionCore)
            .GetField("_timeouts", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(core)!;
        timeouts[1] = DetectionCore.MaxTimeoutsPerRule;

        var sw = Stopwatch.StartNew();
        for (var i = 1; i <= 10; i++)
            core.Process(Ev(i, new string('a', 40) + "!"));
        sw.Stop();

        Assert.True(sw.ElapsedMilliseconds < 200);
        Assert.Equal(10, core.SkippedEvents[1]);
        Assert.Contains("skipped for the remaining 10", core.Warnings(_ => "weak").Single());
    }

    [Fact]
    public void DefaultRules_AllUseTheLinearEngine()
    {
        foreach (var rule in DbSeeder.DefaultRules())
            Assert.False(DetectionCore.TryCompile(rule, out _)!.Backtracking, rule.Name);
    }

    // ---- 03: only public addresses leave the machine, in canonical form ----

    [Theory]
    [InlineData("::ffff:10.0.0.5")]
    [InlineData("::ffff:192.168.1.5")]
    [InlineData("::")]
    [InlineData("::127.0.0.1")]
    [InlineData("100.64.1.1")]
    [InlineData("100.127.255.254")]
    [InlineData("192.0.0.1")]
    [InlineData("192.0.2.1")]
    [InlineData("198.18.0.1")]
    [InlineData("198.19.255.1")]
    [InlineData("198.51.100.7")]
    [InlineData("203.0.113.9")]
    [InlineData("255.255.255.255")]
    [InlineData("2001:db8::1")]
    [InlineData("64:ff9b::a00:1")]
    [InlineData("2002:a00:1::1")]
    [InlineData("2001::1")]
    [InlineData("3fff::1")]
    [InlineData("fe80::1%7")]
    [InlineData("fd00::1")]
    [InlineData("ff02::1")]
    [InlineData("")]
    [InlineData("example.com")]
    public void PrivateAndReservedAddresses_AreNeverPublic(string ip) =>
        Assert.False(IpAddressPolicy.IsPublic(ip), ip);

    [Theory]
    [InlineData("8.8.8.8", "8.8.8.8")]
    [InlineData("::ffff:8.8.8.8", "8.8.8.8")]
    [InlineData("2001:4860:4860::8888", "2001:4860:4860::8888")]
    [InlineData("2001:4860:4860:0:0:0:0:8888", "2001:4860:4860::8888")]
    [InlineData("100.63.255.255", "100.63.255.255")]
    [InlineData("100.128.0.1", "100.128.0.1")]
    [InlineData("172.32.0.1", "172.32.0.1")]
    public void PublicAddresses_AreCanonicalised(string ip, string canonical)
    {
        Assert.True(IpAddressPolicy.TryGetPublic(ip, out var c));
        Assert.Equal(canonical, c);
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public List<Uri> Uris { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Uris.Add(request.RequestUri!);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("{}") });
        }
    }

    [Fact]
    public async Task Provider_ReceivesCanonicalAddress_AndNeverAMappedPrivateOne()
    {
        var handler = new RecordingHandler();
        var options = Options.Create(new EnrichmentOptions { GreyNoiseApiKey = "test" });
        var provider = new GreyNoiseProvider(new HttpClient(handler), options, NullLogger<GreyNoiseProvider>.Instance);

        var skipped = await provider.LookupAsync("::ffff:10.0.0.5", default);
        await provider.LookupAsync("::ffff:8.8.8.8", default);

        Assert.Equal(ThreatVerdict.Skipped, skipped.Verdict);
        var uri = Assert.Single(handler.Uris);
        Assert.EndsWith("/v3/community/8.8.8.8", uri.AbsolutePath);
    }

    // ---- 07: failed lookups never overwrite a good verdict ----

    private sealed class FixedProvider(ReputationResult result) : IThreatIntelProvider
    {
        public ReputationResult Result { get; set; } = result;
        public string Name => "VirusTotal";
        public string Slug => "virustotal";
        public string ApiKeySetting => "Enrichment:VirusTotalApiKey";
        public string SignupUrl => "";
        public string QuotaNote => "";
        public string Description => "";
        public bool IsConfigured => true;
        public int MaxPerRun => 10;
        public TimeSpan MinInterval => TimeSpan.Zero;
        public string WebLink(string ip) => "";
        public Task<ReputationResult> LookupAsync(string ip, CancellationToken ct) => Task.FromResult(Result);
    }

    private static AppDbContext InMemoryDb() =>
        new(new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);

    [Fact]
    public async Task FailedRefresh_KeepsTheEarlierVerdict()
    {
        await using var db = InMemoryDb();
        var provider = new FixedProvider(new ReputationResult(ThreatVerdict.Malicious, "12/90 engines", 13));
        var service = new ThreatIntelService(db, [provider], new ProviderThrottle(),
            Options.Create(new EnrichmentOptions()), NullLogger<ThreatIntelService>.Instance);

        await service.RefreshAsync("8.8.8.8", provider, waitForSlot: false, default);
        provider.Result = ReputationResult.Failed("Rate limit: try again in 12 s");
        var row = await service.RefreshAsync("8.8.8.8", provider, waitForSlot: false, default);

        Assert.Equal(ThreatVerdict.Malicious, row.Verdict);
        Assert.Equal(13, row.Score);
        Assert.Equal("12/90 engines", row.Summary);
        Assert.Equal("Rate limit: try again in 12 s", row.LastAttemptError);
        Assert.Single(db.IpReputations);

        // The next successful answer replaces it and clears the failure note.
        provider.Result = new ReputationResult(ThreatVerdict.Benign, "0/90 engines", 0);
        row = await service.RefreshAsync("8.8.8.8", provider, waitForSlot: false, default);
        Assert.Equal(ThreatVerdict.Benign, row.Verdict);
        Assert.Null(row.LastAttemptError);
    }

    [Fact]
    public async Task FirstLookupError_IsStoredWhenThereIsNothingBetter()
    {
        await using var db = InMemoryDb();
        var provider = new FixedProvider(ReputationResult.Failed("API key rejected"));
        var service = new ThreatIntelService(db, [provider], new ProviderThrottle(),
            Options.Create(new EnrichmentOptions()), NullLogger<ThreatIntelService>.Instance);

        var row = await service.RefreshAsync("8.8.8.8", provider, waitForSlot: false, default);
        Assert.Equal(ThreatVerdict.Error, row.Verdict);
        Assert.Equal("API key rejected", row.Error);
    }

    // ---- 10: alert fan-out ----

    [Fact]
    public void CapPerRule_MergesTheLongTailWithoutLosingEvidence()
    {
        var core = new DetectionCore([DetectionCore.TryCompile(Signature("attack"), out _)!]);
        long id = 0;
        for (var i = 0; i < 1500; i++)
        {
            var ip = $"10.{i / 250}.{i % 250}.1";
            var events = i < 10 ? 5 : 1;   // ten big sources, a long tail of one-event sources
            for (var k = 0; k < events; k++)
                core.Process(Ev(++id, "/?q=attack", ip));
        }

        var capped = DetectionCore.CapPerRule(core.Hits, 1000);
        Assert.Equal(1001, capped.Count);
        Assert.Equal(core.Hits.Sum(h => h.EventIds.Count), capped.Sum(h => h.EventIds.Count));
        Assert.All(capped.Take(10), h => Assert.Equal(5, h.EventIds.Count));
        var merged = capped.Single(h => h.MergedSources > 0);
        Assert.Equal(500, merged.MergedSources);
        Assert.Equal("500 other IPs", merged.Ip);
    }

    [Fact]
    public void CapPerRule_LeavesSmallResultsAlone()
    {
        var core = new DetectionCore([DetectionCore.TryCompile(Signature("attack"), out _)!]);
        core.Process(Ev(1, "/?q=attack", "198.51.100.1"));
        core.Process(Ev(2, "/?q=attack", "198.51.100.2"));
        Assert.Equal(2, DetectionCore.CapPerRule(core.Hits, 1000).Count);
    }

    // ---- 29: evaluation validity ----

    [Fact]
    public void Evaluation_ReportsUnparsedAttacks_AndEndToEndMetrics()
    {
        var labels = new Dictionary<int, string>
        {
            [1] = "sqli", [2] = "normal", [3] = "sqli", [4] = "xss", [5] = "normal", [6] = "malformed"
        };
        var eventLines = new HashSet<int> { 1, 2, 3 };   // 4 and 5 could not be parsed
        var flagged = new Dictionary<int, HashSet<AttackType>> { [1] = [AttackType.SqlInjection] };

        var r = EvaluationService.Compute(labels, eventLines, flagged, [1], []);

        Assert.Equal(new Metrics("All attacks", TP: 1, FP: 0, FN: 1, TN: 1), r.Overall);
        Assert.Equal(1, r.UnparsedMalicious);
        Assert.Equal(1, r.UnparsedNormal);
        Assert.Equal(3, r.IgnoredLines);
        Assert.Equal(1, r.EndToEnd.TP);
        Assert.Equal(2, r.EndToEnd.FN);
        Assert.Equal(2, r.EndToEnd.TN);
        Assert.Equal(1.0 / 3, r.EndToEnd.Recall, 6);
    }

    [Fact]
    public void UniquePathRatio_IsNotSkewedByTheTrackingCap()
    {
        var acc = new IpFeatureAccumulator();
        for (var i = 0; i < 20_000; i++)
            acc.Add(new DetectionEvent(i, "198.51.100.9", T0.AddMilliseconds(i * 100), "GET", "/p" + i, 404, "ua", null));

        var profile = acc.Profiles.Single();
        var ratio = IpFeatureAccumulator.RawValues(profile)[4];
        Assert.InRange(ratio, 0.99, 1.0);
    }
}
