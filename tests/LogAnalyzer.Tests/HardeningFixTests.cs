using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Reflection;
using System.Text;
using LogAnalyzer.Web.Controllers;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Helpers;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace LogAnalyzer.Tests;

/// <summary>Regression tests for the Low/Info findings of the 2026-11-17 audit (11-30).</summary>
public class HardeningFixTests
{
    // ---- 13: admin pages are re-checked against the database ----

    [Fact]
    public void RequiresAdmin_DetectsAdminOnlyActions()
    {
        Assert.True(RevalidateSessionFilter.RequiresAdmin([new AuthorizeAttribute { Roles = Roles.Admin }]));
        Assert.True(RevalidateSessionFilter.RequiresAdmin([new AuthorizeAttribute { Roles = "Analyst, Admin" }]));
        Assert.False(RevalidateSessionFilter.RequiresAdmin([new AuthorizeAttribute()]));
        Assert.False(RevalidateSessionFilter.RequiresAdmin([new AuthorizeAttribute { Roles = Roles.Analyst }]));
    }

    // ---- 14: last-admin guard ----

    private static AppUser Admin(string id, bool disabled = false) => new() { Id = id, IsDisabled = disabled };

    [Fact]
    public void LastAdminGuard_AllowsDemotingADisabledAdmin()
    {
        var active = Admin("s");
        var disabled = Admin("d", disabled: true);
        Assert.False(UsersController.IsLastActiveAdmin(disabled, targetIsAdmin: true, [active, disabled]));
    }

    [Fact]
    public void LastAdminGuard_ProtectsTheOnlyActiveAdmin()
    {
        var active = Admin("s");
        Assert.True(UsersController.IsLastActiveAdmin(active, true, [active, Admin("d", disabled: true)]));
        Assert.False(UsersController.IsLastActiveAdmin(active, true, [active, Admin("t")]));
        Assert.False(UsersController.IsLastActiveAdmin(Admin("x"), targetIsAdmin: false, [active]));
    }

    [Fact]
    public async Task LastAdminGuard_ConcurrentChangesAreSerialised()
    {
        var field = typeof(UsersController).GetField("AdminStateLock", BindingFlags.NonPublic | BindingFlags.Static)!;
        var gate = (SemaphoreSlim)field.GetValue(null)!;
        Assert.Equal(1, gate.CurrentCount);
        await gate.WaitAsync();
        try
        {
            Assert.False(await gate.WaitAsync(0));   // a second admin change has to wait
        }
        finally
        {
            gate.Release();
        }
    }

    // ---- 19: control characters never reach the audit trail ----

    [Fact]
    public void AuditClean_RemovesControlCharacters()
    {
        var cleaned = AuditLog.Clean("x\r\ninfo: User admin logged in\u001b[0m\0@x");
        Assert.DoesNotContain(cleaned!, char.IsControl);
        Assert.Equal("x  info: User admin logged in [0m @x", cleaned);
        Assert.Null(AuditLog.Clean(null));
        Assert.Equal("plain", AuditLog.Clean("plain"));
    }

    [Fact]
    public void LoginModel_RejectsControlCharactersInEmail()
    {
        var model = new LoginViewModel { Email = "a@b.c\r\nforged", Password = "x" };
        Assert.False(Validator.TryValidateObject(model, new ValidationContext(model), [], validateAllProperties: true));
    }

    // ---- 17: quotas, redirects, big bodies ----

    [Fact]
    public void DailyBudget_StopsAtTheLimit()
    {
        var throttle = new ProviderThrottle();
        Assert.True(throttle.TryConsumeDaily("AbuseIPDB", 2));
        Assert.True(throttle.TryConsumeDaily("AbuseIPDB", 2));
        Assert.False(throttle.TryConsumeDaily("AbuseIPDB", 2));
        Assert.True(throttle.TryConsumeDaily("GreyNoise", 2));
        Assert.True(throttle.TryConsumeDaily("VirusTotal", 0));   // 0 = no limit
    }

    private sealed class CountingHandler(Func<HttpResponseMessage> respond) : HttpMessageHandler
    {
        public int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(respond());
        }
    }

    private static AbuseIpDbProvider Abuse(HttpMessageHandler handler) =>
        new(new HttpClient(handler) { MaxResponseContentBufferSize = 1_000_000 },
            Options.Create(new EnrichmentOptions { AbuseIpDbApiKey = "test" }), NullLogger<AbuseIpDbProvider>.Instance);

    [Fact]
    public async Task Provider_RedirectIsAnError()
    {
        var handler = new CountingHandler(() => new HttpResponseMessage(HttpStatusCode.Found)
        {
            Headers = { Location = new Uri("https://evil.example/collect") }
        });
        var r = await Abuse(handler).LookupAsync("8.8.8.8", default);
        Assert.Equal(ThreatVerdict.Error, r.Verdict);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task Provider_HugeBodyIsAnError()
    {
        var handler = new CountingHandler(() => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"data\":\"" + new string('a', 2_000_000) + "\"}", Encoding.UTF8, "application/json")
        });
        var r = await Abuse(handler).LookupAsync("8.8.8.8", default);
        Assert.Equal(ThreatVerdict.Error, r.Verdict);
    }

    // ---- 24: one canonical form for client IPs ----

    [Theory]
    [InlineData("2001:DB8:0:0::1", "2001:db8::1")]
    [InlineData("::FFFF:198.51.100.7", "198.51.100.7")]
    [InlineData("fe80::1%7", "fe80::1")]
    [InlineData("203.0.113.9", "203.0.113.9")]
    [InlineData("1.2", "1.2")]
    [InlineData("crawl-66-249-66-1.googlebot.com", "crawl-66-249-66-1.googlebot.com")]
    [InlineData("-", "-")]
    public void Canonical_NormalisesOnlyRealAddresses(string raw, string expected) =>
        Assert.Equal(expected, IpAddressPolicy.Canonical(raw));

    [Fact]
    public void Parser_StoresTheCanonicalIpv6Form()
    {
        Assert.True(new CombinedLogParser().TryParse(
            "2001:DB8:0:0::1 - - [17/Nov/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"ua\"", out var p));
        Assert.Equal("2001:db8::1", p!.ClientIp);
    }

    // ---- 28: no automatic lookups unless switched on ----

    private sealed class SpyProvider : IThreatIntelProvider
    {
        public int Calls;
        public string Name => "AbuseIPDB";
        public string Slug => "abuseipdb";
        public string ApiKeySetting => "Enrichment:AbuseIpDbApiKey";
        public string SignupUrl => "";
        public string QuotaNote => "";
        public string Description => "";
        public bool IsConfigured => true;
        public int MaxPerRun => 100;
        public TimeSpan MinInterval => TimeSpan.Zero;
        public string WebLink(string ip) => "";
        public Task<ReputationResult> LookupAsync(string ip, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(new ReputationResult(ThreatVerdict.Benign, "ok", 0));
        }
    }

    [Theory]
    [InlineData(false, 0)]
    [InlineData(true, 1)]
    public async Task AutoLookup_ControlsTheWorkerLookups(bool autoLookup, int expectedCalls)
    {
        await using var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        db.Alerts.Add(new Alert { Id = 1, LogFileId = 7, RuleId = 1, SourceIp = "8.8.8.8", Title = "t" });
        await db.SaveChangesAsync();

        var spy = new SpyProvider();
        var options = new EnrichmentOptions { AutoLookup = autoLookup, GreyNoiseDowngradeBenign = false };
        var service = new ThreatIntelService(db, [spy], new ProviderThrottle(), Options.Create(options),
            NullLogger<ThreatIntelService>.Instance);

        var summary = await service.RunForLogFileAsync(7, default);
        Assert.Equal(expectedCalls, spy.Calls);
        Assert.Equal(expectedCalls, summary.Lookups);
    }

    // ---- 20: bounded labels ----

    [Fact]
    public void ParseLabels_IgnoresHugeLabelsAndStopsAtTheLineCount()
    {
        var csv = "1,sqli\n2," + new string('x', 100) + "\n3,normal\n0,xss\n99,xss\n4,xss\n5,normal\n";
        var labels = EvaluationService.ParseLabels(new MemoryStream(Encoding.UTF8.GetBytes(csv)), maxLine: 4);
        Assert.Equal(new Dictionary<int, string> { [1] = "sqli", [3] = "normal", [4] = "xss" }, labels);
    }

    [Fact]
    public void ParseLabels_SkipsOverlongLinesWithoutReadingThemIntoMemory()
    {
        var csv = "1," + new string('y', 5_000_000) + "\n2,sqli\n";
        var labels = EvaluationService.ParseLabels(new MemoryStream(Encoding.UTF8.GetBytes(csv)));
        Assert.Equal("sqli", Assert.Single(labels).Value);
    }

    // ---- 25: triage validation ----

    [Fact]
    public void AlertUpdate_RejectsUnknownStatus()
    {
        var model = new AlertUpdateModel { Status = (AlertStatus)99 };
        var results = new List<ValidationResult>();
        Assert.False(Validator.TryValidateObject(model, new ValidationContext(model), results, validateAllProperties: true));
        Assert.Equal("Invalid status.", Assert.Single(results).ErrorMessage);
    }

    // ---- 27: every action states its HTTP verb ----

    [Fact]
    public void EveryControllerAction_HasAnExplicitHttpVerb()
    {
        var actions = typeof(HomeController).Assembly.GetTypes()
            .Where(t => typeof(Controller).IsAssignableFrom(t) && !t.IsAbstract)
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(m => !m.IsSpecialName && m.GetCustomAttribute<NonActionAttribute>() is null)
            .ToList();
        Assert.NotEmpty(actions);
        foreach (var m in actions)
            Assert.True(m.GetCustomAttributes().OfType<IActionHttpMethodProvider>().Any(),
                $"{m.DeclaringType!.Name}.{m.Name} has no [HttpGet]/[HttpPost]");
    }

    // ---- 30: CSV formula neutralisation ----

    [Theory]
    [InlineData("=1+1")]
    [InlineData("＝1+1")]
    [InlineData(" =1+1")]
    [InlineData(" +cmd")]
    [InlineData("\n=1+1")]
    [InlineData("＠SUM(A1)")]
    public void Csv_NeutralisesFormulaStarters(string value) =>
        Assert.StartsWith("\"'", Format.Csv(value));

    [Fact]
    public void Csv_LeavesNormalTextAlone() => Assert.Equal("\"GET /index.php\"", Format.Csv("GET /index.php"));
}
