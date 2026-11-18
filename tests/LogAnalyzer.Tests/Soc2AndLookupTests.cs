using System.Text.Json;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace LogAnalyzer.Tests;

/// <summary>Multi-indicator threat lookup and the SOC 2 escalation workflow.</summary>
public class Soc2AndLookupTests
{
    // ---- indicator parsing ----

    [Theory]
    [InlineData("8.8.8.8", IndicatorType.Ip, "8.8.8.8")]
    [InlineData("  2001:4860:4860:0:0:0:0:8888 ", IndicatorType.Ip, "2001:4860:4860::8888")]
    [InlineData("::ffff:8.8.4.4", IndicatorType.Ip, "8.8.4.4")]
    [InlineData("Example.COM", IndicatorType.Domain, "example.com")]
    [InlineData("opensteprun.com", IndicatorType.Domain, "opensteprun.com")]
    [InlineData("evil[.]example[.]org", IndicatorType.Domain, "evil.example.org")]
    [InlineData("hxxps://bad.example.net/path?x=1", IndicatorType.Domain, "bad.example.net")]
    [InlineData("https://203.0.113.5:8443/login", IndicatorType.Ip, "203.0.113.5")]
    [InlineData("*.cdn.example.com", IndicatorType.Domain, "cdn.example.com")]
    [InlineData("bücher.example", IndicatorType.Domain, "xn--bcher-kva.example")]
    [InlineData("44D88612FEA8A8F36DE82E1278ABB02F", IndicatorType.Hash, "44d88612fea8a8f36de82e1278abb02f")]
    [InlineData("3395856ce81f2b7382dee72602f798b642f14140", IndicatorType.Hash, "3395856ce81f2b7382dee72602f798b642f14140")]
    [InlineData("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", IndicatorType.Hash,
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")]
    public void Parser_RecognisesIpsDomainsAndHashes(string raw, IndicatorType type, string value)
    {
        Assert.True(IndicatorParser.TryParse(raw, out var indicator, out _), raw);
        Assert.Equal(type, indicator.Type);
        Assert.Equal(value, indicator.Value);
    }

    [Theory]
    [InlineData("")]
    [InlineData("1.2")]
    [InlineData("not a domain")]
    [InlineData("localhost")]
    [InlineData("abc123")]
    [InlineData("44d88612fea8a8f36de82e1278abb02")]  // 31 hex chars
    [InlineData("-bad-.com")]
    [InlineData("<script>.com")]
    public void Parser_RejectsEverythingElse(string raw)
    {
        Assert.False(IndicatorParser.TryParse(raw, out _, out var error));
        Assert.Equal(IndicatorParser.Help, error);
    }

    [Theory]
    [InlineData("intranet.corp", false)]
    [InlineData("printer.local", false)]
    [InlineData("db01.internal", false)]
    [InlineData("router.home.arpa", false)]
    [InlineData("mail.example.org", false)]   // organisation's own domain (configured)
    [InlineData("example.org", false)]
    [InlineData("notexample.org", true)]
    [InlineData("google.com", true)]
    public void InternalDomains_NeverLeaveTheMachine(string domain, bool maySend)
    {
        var indicator = new Indicator(IndicatorType.Domain, domain);
        Assert.Equal(maySend, IndicatorParser.MaySend(indicator, ["example.org"], out _));
    }

    [Fact]
    public void PrivateIps_AreBlocked_HashesAreAllowed()
    {
        Assert.False(IndicatorParser.MaySend(Indicator.ForIp("10.0.0.5"), null, out var reason));
        Assert.Contains("never sent", reason);
        Assert.True(IndicatorParser.MaySend(new Indicator(IndicatorType.Hash, new string('a', 64)), null, out _));
    }

    // ---- VirusTotal domain / file answers ----

    [Fact]
    public void VirusTotal_ParsesDomains()
    {
        using var doc = JsonDocument.Parse("""
            {"data":{"id":"bad.example","type":"domain","attributes":{
              "last_analysis_stats":{"malicious":7,"suspicious":1,"harmless":60,"undetected":20,"timeout":0},
              "reputation":-25,"registrar":"Example Registrar","creation_date":1700000000,
              "categories":{"Forcepoint ThreatSeeker":"phishing","Sophos":"phishing","BitDefender":"malware"}}}}
            """);
        var r = VirusTotalProvider.ParseResponse(doc.RootElement, IndicatorType.Domain);
        Assert.Equal(ThreatVerdict.Malicious, r.Verdict);
        Assert.Equal("Example Registrar", r.Attributes!["Registrar"]);
        Assert.Equal("phishing, malware", r.Attributes["Categories"]);
        Assert.False(r.Attributes.ContainsKey("AS owner"));
    }

    [Fact]
    public void VirusTotal_ParsesFiles()
    {
        using var doc = JsonDocument.Parse("""
            {"data":{"type":"file","attributes":{
              "last_analysis_stats":{"malicious":62,"suspicious":0,"harmless":0,"undetected":8},
              "meaningful_name":"eicar.com","type_description":"Text","size":68,
              "sha256":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
              "popular_threat_classification":{"suggested_threat_label":"virus.eicar/test"}}}}
            """);
        var r = VirusTotalProvider.ParseResponse(doc.RootElement, IndicatorType.Hash);
        Assert.Equal(ThreatVerdict.Malicious, r.Verdict);
        Assert.Equal("eicar.com", r.Attributes!["File name"]);
        Assert.Equal("virus.eicar/test", r.Attributes["Threat label"]);
        Assert.Equal("68 bytes", r.Attributes["Size"]);
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public List<Uri> Uris { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Uris.Add(request.RequestUri!);
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.NotFound) { Content = new StringContent("{}") });
        }
    }

    [Theory]
    [InlineData(IndicatorType.Domain, "example.com", "/api/v3/domains/example.com", "VirusTotal has never seen", false)]
    [InlineData(IndicatorType.Hash, "44d88612fea8a8f36de82e1278abb02f", "/api/v3/files/44d88612fea8a8f36de82e1278abb02f", "never seen this file", true)]
    public async Task VirusTotal_UsesTheRightEndpoint(IndicatorType type, string value, string path, string notFound, bool isFile)
    {
        var handler = new RecordingHandler();
        var vt = new VirusTotalProvider(new HttpClient(handler),
            Options.Create(new EnrichmentOptions { VirusTotalApiKey = "test" }), NullLogger<VirusTotalProvider>.Instance);
        var r = await vt.LookupAsync(new Indicator(type, value), default);
        Assert.Equal(path, Assert.Single(handler.Uris).AbsolutePath);
        Assert.Equal(ThreatVerdict.NotFound, r.Verdict);
        if (isFile) Assert.Contains(notFound, r.Summary);
        Assert.Contains(isFile ? "/gui/file/" : "/gui/domain/", vt.WebLink(new Indicator(type, value)));
    }

    [Fact]
    public async Task IpOnlyProvider_SkipsDomainsWithoutCallingTheApi()
    {
        var handler = new RecordingHandler();
        var abuse = new AbuseIpDbProvider(new HttpClient(handler),
            Options.Create(new EnrichmentOptions { AbuseIpDbApiKey = "test" }), NullLogger<AbuseIpDbProvider>.Instance);
        var r = await abuse.LookupAsync(new Indicator(IndicatorType.Domain, "example.com"), default);
        Assert.Equal(ThreatVerdict.Skipped, r.Verdict);
        Assert.Empty(handler.Uris);
        Assert.False(abuse.Supports(IndicatorType.Hash));
    }

    // ---- "Look up" asks every configured provider that supports the type ----

    private sealed class FakeProvider(string name, bool configured, params IndicatorType[] types) : IThreatIntelProvider
    {
        public int Calls;
        public string Name => name;
        public string Slug => name.ToLowerInvariant();
        public string ApiKeySetting => "Enrichment:" + name;
        public string SignupUrl => "";
        public string QuotaNote => "";
        public string Description => "";
        public bool IsConfigured => configured;
        public int MaxPerRun => 10;
        public TimeSpan MinInterval => TimeSpan.Zero;
        public string WebLink(string ip) => "";
        public IReadOnlyCollection<IndicatorType> SupportedTypes => types;
        public Task<ReputationResult> LookupAsync(string ip, CancellationToken ct) => LookupAsync(Indicator.ForIp(ip), ct);
        public Task<ReputationResult> LookupAsync(Indicator indicator, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(new ReputationResult(ThreatVerdict.Suspicious, $"{name} says hi"));
        }
    }

    private static AppDbContext InMemoryDb() =>
        new(new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);

    [Fact]
    public async Task LookupEverywhere_OnlyAsksConfiguredProvidersThatSupportTheType()
    {
        await using var db = InMemoryDb();
        var ipOnly = new FakeProvider("IpOnly", true, IndicatorType.Ip);
        var all = new FakeProvider("All", true, IndicatorType.Ip, IndicatorType.Domain, IndicatorType.Hash);
        var noKey = new FakeProvider("NoKey", false, IndicatorType.Ip, IndicatorType.Domain);
        var service = new ThreatIntelService(db, [ipOnly, all, noKey], new ProviderThrottle(),
            Options.Create(new EnrichmentOptions()), NullLogger<ThreatIntelService>.Instance);

        var domain = await service.LookupEverywhereAsync(new Indicator(IndicatorType.Domain, "example.com"), TimeSpan.Zero, default);
        Assert.Equal(["All"], domain.Select(r => r.Provider));
        Assert.Equal(IndicatorType.Domain, domain[0].Kind);

        var ip = await service.LookupEverywhereAsync(Indicator.ForIp("8.8.8.8"), TimeSpan.Zero, default);
        Assert.Equal(["IpOnly", "All"], ip.Select(r => r.Provider));
        Assert.Equal(0, noKey.Calls);

        // A second look-up within CacheDays reuses the cached answers.
        await service.LookupEverywhereAsync(Indicator.ForIp("8.8.8.8"), TimeSpan.Zero, default);
        Assert.Equal(1, ipOnly.Calls);
        Assert.Equal(2, all.Calls);
    }

    [Fact]
    public async Task LookupEverywhere_NeverSendsInternalDomains()
    {
        await using var db = InMemoryDb();
        var all = new FakeProvider("All", true, IndicatorType.Ip, IndicatorType.Domain);
        var service = new ThreatIntelService(db, [all], new ProviderThrottle(),
            Options.Create(new EnrichmentOptions { InternalDomains = ["example.org"] }), NullLogger<ThreatIntelService>.Instance);

        var r = await service.LookupEverywhereAsync(new Indicator(IndicatorType.Domain, "vpn.example.org"), TimeSpan.Zero, default);
        Assert.Equal(ThreatVerdict.Skipped, Assert.Single(r).Verdict);
        Assert.Equal(0, all.Calls);
    }

    // ---- SOC 2 escalation ownership ----

    private static Alert Escalated(string? owner = null, EscalationVerdict? verdict = null) => new()
    {
        Status = AlertStatus.Investigating,
        EscalatedAt = DateTime.UtcNow,
        AssignedToId = owner,
        Verdict = verdict
    };

    [Fact]
    public void OnlySoc2_CanTakeUnownedEscalations()
    {
        Assert.True(SocPermissions.CanClaim(false, AnalystTier.Soc2, Escalated()));
        Assert.True(SocPermissions.CanClaim(true, null, Escalated()));
        Assert.False(SocPermissions.CanClaim(false, AnalystTier.Soc1, Escalated()));
        Assert.False(SocPermissions.CanClaim(false, AnalystTier.Soc2, Escalated(owner: "someone")));
        Assert.False(SocPermissions.CanClaim(false, AnalystTier.Soc2, new Alert { Status = AlertStatus.New }));
    }

    [Fact]
    public void OnlyTheOwner_GivesOrChangesTheVerdict()
    {
        var alert = Escalated(owner: "owner", verdict: EscalationVerdict.Malicious);
        Assert.True(SocPermissions.CanGiveVerdict(false, AnalystTier.Soc2, alert, "owner"));
        Assert.False(SocPermissions.CanGiveVerdict(false, AnalystTier.Soc2, alert, "second-opinion"));
        Assert.False(SocPermissions.CanGiveVerdict(true, null, alert, "an-admin"));
        Assert.True(SocPermissions.CanUpdate(false, AnalystTier.Soc2, alert, "owner", AlertStatus.Closed));
        Assert.False(SocPermissions.CanUpdate(false, AnalystTier.Soc2, alert, "second-opinion", AlertStatus.Closed));
        Assert.Empty(SocPermissions.AllowedStatuses(false, AnalystTier.Soc1, alert, "escalator"));
    }

    [Fact]
    public void OwnerOrAdmin_CanRelease()
    {
        var alert = Escalated(owner: "owner");
        Assert.True(SocPermissions.CanRelease(false, alert, "owner"));
        Assert.True(SocPermissions.CanRelease(true, alert, "admin"));
        Assert.False(SocPermissions.CanRelease(false, alert, "other"));
        Assert.False(SocPermissions.CanRelease(true, Escalated(), "admin"));
    }

    [Theory]
    [InlineData(EscalationVerdict.Malicious, AlertStatus.Closed)]
    [InlineData(EscalationVerdict.Benign, AlertStatus.Closed)]
    [InlineData(EscalationVerdict.FalsePositive, AlertStatus.FalsePositive)]
    [InlineData(EscalationVerdict.KeepMonitoring, AlertStatus.Investigating)]
    public void Verdict_SetsTheMatchingStatus(EscalationVerdict verdict, AlertStatus status) =>
        Assert.Equal(status, SocPermissions.StatusFor(verdict));

    [Fact]
    public void HubState_FollowsOwnerAndVerdict()
    {
        Assert.Equal(SocPermissions.HubState.Waiting, SocPermissions.StateOf(Escalated()));
        Assert.Equal(SocPermissions.HubState.InProgress, SocPermissions.StateOf(Escalated(owner: "x")));
        Assert.Equal(SocPermissions.HubState.Decided, SocPermissions.StateOf(Escalated(owner: "x", verdict: EscalationVerdict.Benign)));
    }

    // ---- notifications ----

    [Fact]
    public async Task Escalation_NotifiesEverySoc2AnalystButNotTheActor()
    {
        await using var db = InMemoryDb();
        db.Users.AddRange(
            new AppUser { Id = "soc2-a", UserName = "a", Tier = AnalystTier.Soc2 },
            new AppUser { Id = "soc2-b", UserName = "b", Tier = AnalystTier.Soc2 },
            new AppUser { Id = "soc2-off", UserName = "c", Tier = AnalystTier.Soc2, IsDisabled = true },
            new AppUser { Id = "soc1", UserName = "d", Tier = AnalystTier.Soc1 });
        var alert = new Alert { Id = 67, Title = "SQL injection from 185.220.101.45", EscalationReason = "needs L2" };
        await db.SaveChangesAsync();

        var service = new NotificationService(db, null!, NullLogger<NotificationService>.Instance);
        var count = await service.NotifySoc2Async(alert, "soc2-b", "Demo Analyst");

        Assert.Equal(1, count);
        var n = Assert.Single(db.Notifications);
        Assert.Equal("soc2-a", n.UserId);
        Assert.Equal("Demo Analyst escalated alert #67 to SOC 2", n.Title);
        Assert.Equal("/Alerts/Details/67", n.Link);
        Assert.Null(n.ReadAt);
    }

    [Fact]
    public async Task NotifyUser_SkipsTheActorAndDeletedAccounts()
    {
        await using var db = InMemoryDb();
        db.Users.Add(new AppUser { Id = "escalator", UserName = "e" });
        await db.SaveChangesAsync();
        var service = new NotificationService(db, null!, NullLogger<NotificationService>.Instance);

        await service.NotifyUserAsync("escalator", "escalator", "claim", "self", null, "/x");
        await service.NotifyUserAsync("gone", "owner", "claim", "deleted user", null, "/x");
        await service.NotifyUserAsync("escalator", "owner", "claim", "taken", null, "//evil.example");

        var n = Assert.Single(db.Notifications);
        Assert.Equal("taken", n.Title);
        Assert.Null(n.Link);   // never an external link
    }
}
