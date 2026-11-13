using System.Net;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace LogAnalyzer.Tests;

/// <summary>
/// The providers are tested against recorded-style JSON responses through a fake HTTP handler,
/// so the parsing and error handling are verified without API keys or network access.
/// </summary>
public class ThreatIntelProviderTests
{
    private sealed class FakeHandler(HttpStatusCode status, string body) : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request);
            return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body) });
        }
    }

    private static IOptions<EnrichmentOptions> Keys(bool configured = true) => Options.Create(new EnrichmentOptions
    {
        AbuseIpDbApiKey = configured ? "test-abuse" : null,
        GreyNoiseApiKey = configured ? "test-gn" : null,
        VirusTotalApiKey = configured ? "test-vt" : null
    });

    [Fact]
    public async Task AbuseIpDb_maps_score_to_verdict_and_sends_key_header()
    {
        const string json = """
            {"data":{"ipAddress":"185.220.101.45","isPublic":true,"isWhitelisted":false,"abuseConfidenceScore":100,
             "countryCode":"DE","usageType":"Reserved","isp":"Tor Exit","domain":"example.org","isTor":true,
             "totalReports":5120,"numDistinctUsers":610,"lastReportedAt":"2026-11-12T10:00:00+00:00"}}
            """;
        var handler = new FakeHandler(HttpStatusCode.OK, json);
        var provider = new AbuseIpDbProvider(new HttpClient(handler), Keys(), NullLogger<AbuseIpDbProvider>.Instance);

        var r = await provider.LookupAsync("185.220.101.45", default);

        Assert.Equal(ThreatVerdict.Malicious, r.Verdict);
        Assert.Equal(100, r.Score);
        Assert.Equal("Yes", r.Attributes!["Tor exit node"]);
        var request = Assert.Single(handler.Requests);
        Assert.Equal("test-abuse", request.Headers.GetValues("Key").Single());
        Assert.Contains("ipAddress=185.220.101.45", request.RequestUri!.Query);
    }

    [Fact]
    public async Task GreyNoise_benign_scanner_and_not_found()
    {
        const string benign = """
            {"ip":"162.142.125.9","noise":true,"riot":false,"classification":"benign","name":"Censys",
             "link":"https://viz.greynoise.io/ip/162.142.125.9","last_seen":"2026-11-12","message":"Success"}
            """;
        var provider = new GreyNoiseProvider(new HttpClient(new FakeHandler(HttpStatusCode.OK, benign)), Keys(), NullLogger<GreyNoiseProvider>.Instance);
        var r = await provider.LookupAsync("162.142.125.9", default);
        Assert.Equal(ThreatVerdict.Benign, r.Verdict);
        Assert.Contains("Censys", r.Summary);

        const string notFound = """{"ip":"1.2.3.4","noise":false,"riot":false,"message":"IP not observed scanning the internet or contained in RIOT data set."}""";
        provider = new GreyNoiseProvider(new HttpClient(new FakeHandler(HttpStatusCode.NotFound, notFound)), Keys(), NullLogger<GreyNoiseProvider>.Instance);
        r = await provider.LookupAsync("1.2.3.4", default);
        Assert.Equal(ThreatVerdict.NotFound, r.Verdict);
    }

    [Fact]
    public async Task GreyNoise_riot_is_benign()
    {
        const string json = """{"ip":"8.8.8.8","noise":false,"riot":true,"classification":"benign","name":"Google Public DNS"}""";
        var provider = new GreyNoiseProvider(new HttpClient(new FakeHandler(HttpStatusCode.OK, json)), Keys(), NullLogger<GreyNoiseProvider>.Instance);
        var r = await provider.LookupAsync("8.8.8.8", default);
        Assert.Equal(ThreatVerdict.Benign, r.Verdict);
        Assert.Contains("Google Public DNS", r.Summary);
    }

    [Fact]
    public async Task VirusTotal_counts_engines()
    {
        const string json = """
            {"data":{"id":"45.146.164.110","type":"ip_address","attributes":{
              "last_analysis_stats":{"malicious":7,"suspicious":1,"undetected":20,"harmless":64,"timeout":0},
              "reputation":-12,"as_owner":"Example Hosting","asn":12345,"country":"RU","network":"45.146.164.0/24",
              "last_analysis_date":1794500000}}}
            """;
        var handler = new FakeHandler(HttpStatusCode.OK, json);
        var provider = new VirusTotalProvider(new HttpClient(handler), Keys(), NullLogger<VirusTotalProvider>.Instance);

        var r = await provider.LookupAsync("45.146.164.110", default);

        Assert.Equal(ThreatVerdict.Malicious, r.Verdict);
        Assert.Equal(9, r.Score); // (7 + 1) / 92 engines
        Assert.Equal("7", r.Attributes!["Malicious"]);
        Assert.Equal("test-vt", handler.Requests.Single().Headers.GetValues("x-apikey").Single());
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, "API key rejected")]
    [InlineData(HttpStatusCode.TooManyRequests, "quota")]
    [InlineData(HttpStatusCode.InternalServerError, "unavailable")]
    public async Task Http_errors_become_error_results(HttpStatusCode status, string expected)
    {
        var provider = new AbuseIpDbProvider(new HttpClient(new FakeHandler(status, "{}")), Keys(), NullLogger<AbuseIpDbProvider>.Instance);
        var r = await provider.LookupAsync("8.8.8.8", default);
        Assert.Equal(ThreatVerdict.Error, r.Verdict);
        Assert.Contains(expected, r.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Malformed_json_is_an_error_not_an_exception()
    {
        var provider = new VirusTotalProvider(new HttpClient(new FakeHandler(HttpStatusCode.OK, "<html>oops</html>")), Keys(), NullLogger<VirusTotalProvider>.Instance);
        var r = await provider.LookupAsync("8.8.8.8", default);
        Assert.Equal(ThreatVerdict.Error, r.Verdict);
    }

    [Fact]
    public async Task Without_key_or_for_private_ips_nothing_is_sent()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, "{}");
        var unconfigured = new AbuseIpDbProvider(new HttpClient(handler), Keys(configured: false), NullLogger<AbuseIpDbProvider>.Instance);
        Assert.Equal(ThreatVerdict.Skipped, (await unconfigured.LookupAsync("8.8.8.8", default)).Verdict);

        var configured = new GreyNoiseProvider(new HttpClient(handler), Keys(), NullLogger<GreyNoiseProvider>.Instance);
        Assert.Equal(ThreatVerdict.Skipped, (await configured.LookupAsync("192.168.1.10", default)).Verdict);

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Throttle_spaces_calls_and_can_refuse_instead_of_waiting()
    {
        var throttle = new ProviderThrottle();
        var gap = TimeSpan.FromSeconds(30);
        Assert.True(await throttle.TryEnterAsync("vt", gap, wait: false, default));
        Assert.False(await throttle.TryEnterAsync("vt", gap, wait: false, default));
        Assert.True(throttle.RetryAfter("vt", gap) > TimeSpan.FromSeconds(25));
        Assert.True(await throttle.TryEnterAsync("other", gap, wait: false, default));
    }
}
