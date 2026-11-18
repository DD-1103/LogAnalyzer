using System.Net;
using System.Text.Json;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace LogAnalyzer.Tests;

/// <summary>The six vendors added for the threat-intel dashboard and LogAnalyzer's combined verdict.</summary>
public class VendorDashboardTests
{
    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement.Clone();

    private static IOptions<EnrichmentOptions> Keys() => Options.Create(new EnrichmentOptions
    {
        GtiApiKey = "gti-key", RecordedFutureApiKey = "rf-key", OtxApiKey = "otx-key", AbuseChAuthKey = "abusech-key"
    });

    private sealed class Recorder(HttpStatusCode status, string body) : HttpMessageHandler
    {
        public HttpRequestMessage? Request;
        public string? Body;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Request = request;
            Body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
            return new HttpResponseMessage(status) { Content = new StringContent(body) };
        }
    }

    // ---- GTI ----

    [Fact]
    public void Gti_UsesItsOwnAssessment()
    {
        var r = GtiProvider.ParseResponse(Json("""
            {"data":{"type":"ip_address","attributes":{
              "last_analysis_stats":{"malicious":3,"suspicious":1,"harmless":60,"undetected":20},
              "gti_assessment":{"verdict":{"value":"VERDICT_MALICIOUS"},"severity":{"value":"SEVERITY_HIGH"},
                "threat_score":{"value":85},"description":"Known C2 infrastructure",
                "contributing_factors":{"mandiant_analyst_malicious":true,"gavs_detections":3,"normalised_categories":["c2","malware"]}}}}}
            """));
        Assert.Equal(ThreatVerdict.Malicious, r.Verdict);
        Assert.Equal(85, r.Score);
        Assert.Equal("Malicious, threat score 85", r.VendorVerdict);
        Assert.Equal("High", r.Attributes!["Severity"]);
        Assert.Equal("Yes", r.Attributes["Factor: Mandiant analyst malicious"]);
        Assert.Equal("c2, malware", r.Attributes["Factor: Normalised categories"]);
    }

    [Theory]
    [InlineData("VERDICT_SUSPICIOUS", ThreatVerdict.Suspicious, "Suspicious")]
    [InlineData("VERDICT_BENIGN", ThreatVerdict.Benign, "Benign")]
    [InlineData("VERDICT_UNDETECTED", ThreatVerdict.Unknown, "Undetected")]
    public void Gti_MapsEveryVerdict(string value, ThreatVerdict expected, string label)
    {
        var r = GtiProvider.ParseResponse(Json("{\"data\":{\"attributes\":{\"gti_assessment\":{\"verdict\":{\"value\":\"" + value + "\"}}}}}"));
        Assert.Equal(expected, r.Verdict);
        Assert.StartsWith(label, r.VendorVerdict);
    }

    [Fact]
    public void Gti_WithoutAssessment_FallsBackToEngines()
    {
        var r = GtiProvider.ParseResponse(Json("""{"data":{"attributes":{"last_analysis_stats":{"malicious":5,"harmless":50}}}}"""));
        Assert.Equal(ThreatVerdict.Malicious, r.Verdict);
        Assert.Equal("No GTI assessment", r.VendorVerdict);
    }

    [Fact]
    public async Task Gti_SendsKeyAndToolHeader()
    {
        var handler = new Recorder(HttpStatusCode.NotFound, "{}");
        var gti = new GtiProvider(new HttpClient(handler), Keys(), NullLogger<GtiProvider>.Instance);
        var r = await gti.LookupAsync(new Indicator(IndicatorType.Domain, "example.com"), default);
        Assert.Equal("https://www.virustotal.com/api/v3/domains/example.com", handler.Request!.RequestUri!.ToString());
        Assert.Equal("gti-key", handler.Request.Headers.GetValues("x-apikey").Single());
        Assert.Equal("LogAnalyzer", handler.Request.Headers.GetValues("x-tool").Single());
        Assert.Equal(ThreatVerdict.NotFound, r.Verdict);
    }

    // ---- Recorded Future ----

    [Fact]
    public void RecordedFuture_UsesCriticalityLabelsAndRules()
    {
        var r = RecordedFutureProvider.ParseResponse(Json("""
            {"data":{"intelCard":"https://app.recordedfuture.com/live/sc/entity/ip%3A185.220.101.45",
             "risk":{"score":92,"criticality":4,"criticalityLabel":"Very Malicious","riskString":"5/64",
              "riskSummary":"5 of 64 Risk Rules currently observed.",
              "evidenceDetails":[
                {"rule":"Current C&C Server","criticality":4,"criticalityLabel":"Very Malicious","evidenceString":"1 sighting on 1 source"},
                {"rule":"Tor Node","criticality":1,"criticalityLabel":"Unusual","evidenceString":"Tor exit node"}]}}}
            """));
        Assert.Equal(ThreatVerdict.Malicious, r.Verdict);
        Assert.Equal(92, r.Score);
        Assert.Equal("Very Malicious, risk 92", r.VendorVerdict);
        Assert.Equal("Very Malicious - 1 sighting on 1 source", r.Attributes!["Rule: Current C&C Server"]);
        Assert.Equal("5/64", r.Attributes["Rules triggered"]);
    }

    [Theory]
    [InlineData(2, 40, ThreatVerdict.Suspicious, "Suspicious")]
    [InlineData(1, 10, ThreatVerdict.Unknown, "Unusual")]
    [InlineData(0, 0, ThreatVerdict.NotFound, "No current evidence")]
    public void RecordedFuture_MapsCriticality(int criticality, int score, ThreatVerdict expected, string label)
    {
        var r = RecordedFutureProvider.ParseResponse(Json("{\"data\":{\"risk\":{\"score\":" + score + ",\"criticality\":" + criticality + "}}}"));
        Assert.Equal(expected, r.Verdict);
        Assert.StartsWith(label, r.VendorVerdict);
    }

    [Fact]
    public async Task RecordedFuture_RequestFormat()
    {
        var handler = new Recorder(HttpStatusCode.NotFound, "");
        var rf = new RecordedFutureProvider(new HttpClient(handler), Keys(), NullLogger<RecordedFutureProvider>.Instance);
        await rf.LookupAsync(new Indicator(IndicatorType.Hash, new string('a', 64)), default);
        Assert.Equal($"https://api.recordedfuture.com/v2/hash/{new string('a', 64)}?fields=risk,intelCard", handler.Request!.RequestUri!.ToString());
        Assert.Equal("rf-key", handler.Request.Headers.GetValues("X-RFToken").Single());
    }

    // ---- OTX ----

    [Fact]
    public void Otx_CountsPulsesAndMalware()
    {
        var r = OtxProvider.ParseResponse(Json("""
            {"indicator":"185.220.101.45","type_title":"IPv4","reputation":0,"country_name":"Germany","asn":"AS60729",
             "pulse_info":{"count":7,"pulses":[
               {"name":"Tor exit nodes","tags":["tor","scanner"],"malware_families":[],"adversary":""},
               {"name":"Cobalt Strike C2","tags":["c2","tor"],"malware_families":[{"id":"Cobalt Strike","display_name":"Cobalt Strike"}],"adversary":"FIN7"}]}}
            """));
        Assert.Equal(ThreatVerdict.Malicious, r.Verdict);
        Assert.Equal("In 7 pulses", r.VendorVerdict);
        Assert.Equal("Cobalt Strike", r.Attributes!["Malware families"]);
        Assert.Equal("FIN7", r.Attributes["Adversaries"]);
        Assert.StartsWith("tor", r.Attributes["Common tags"]);
    }

    [Theory]
    [InlineData(0, ThreatVerdict.NotFound)]
    [InlineData(2, ThreatVerdict.Suspicious)]
    public void Otx_FewOrNoPulses(int count, ThreatVerdict expected) =>
        Assert.Equal(expected, OtxProvider.ParseResponse(Json("{\"pulse_info\":{\"count\":" + count + ",\"pulses\":[]}}")).Verdict);

    [Theory]
    [InlineData(IndicatorType.Ip, "8.8.8.8", "/api/v1/indicators/IPv4/8.8.8.8/general")]
    [InlineData(IndicatorType.Ip, "2001:4860:4860::8888", "/api/v1/indicators/IPv6/2001%3A4860%3A4860%3A%3A8888/general")]
    [InlineData(IndicatorType.Domain, "example.com", "/api/v1/indicators/domain/example.com/general")]
    [InlineData(IndicatorType.Hash, "44d88612fea8a8f36de82e1278abb02f", "/api/v1/indicators/file/44d88612fea8a8f36de82e1278abb02f/general")]
    public async Task Otx_RequestFormat(IndicatorType type, string value, string path)
    {
        var handler = new Recorder(HttpStatusCode.OK, """{"pulse_info":{"count":0}}""");
        var otx = new OtxProvider(new HttpClient(handler), Keys(), NullLogger<OtxProvider>.Instance);
        await otx.LookupAsync(new Indicator(type, value), default);
        Assert.Equal(path, handler.Request!.RequestUri!.AbsolutePath.Replace("%3a", "%3A"));
        Assert.Equal("otx-key", handler.Request.Headers.GetValues("X-OTX-API-KEY").Single());
    }

    // ---- ThreatFox ----

    private const string ThreatFoxHits = """
        {"query_status":"ok","data":[
          {"id":"1","ioc":"185.220.101.45:443","threat_type":"botnet_cc","threat_type_desc":"Botnet C&C","ioc_type":"ip:port",
           "malware":"win.cobalt_strike","malware_printable":"Cobalt Strike","confidence_level":100,
           "first_seen":"2026-10-01 10:00:00 UTC","last_seen":null,"reporter":"abuse_ch","tags":["c2","CobaltStrike"]},
          {"id":"2","ioc":"185.220.101.450:80","malware_printable":"Other","confidence_level":100}]}
        """;

    [Fact]
    public void ThreatFox_KeepsOnlyTheSearchedIp()
    {
        var r = ThreatFoxProvider.ParseResponse(Json(ThreatFoxHits), Indicator.ForIp("185.220.101.45"));
        Assert.Equal(ThreatVerdict.Malicious, r.Verdict);
        Assert.Equal("Cobalt Strike, confidence 100%", r.VendorVerdict);
        Assert.Equal("Botnet C&C", r.Attributes!["Threat type"]);
        Assert.False(r.Attributes.ContainsKey("Other entries"));   // 185.220.101.450 is not the same IP
    }

    [Fact]
    public void ThreatFox_WildcardMissIsNotFound()
    {
        var r = ThreatFoxProvider.ParseResponse(Json(ThreatFoxHits), Indicator.ForIp("185.220.101.4"));
        Assert.Equal(ThreatVerdict.NotFound, r.Verdict);
        Assert.Equal(ThreatVerdict.NotFound,
            ThreatFoxProvider.ParseResponse(Json("""{"query_status":"no_result","data":"Your search did not yield any results"}"""), null).Verdict);
    }

    [Fact]
    public async Task ThreatFox_PostsJsonWithAuthKey()
    {
        var handler = new Recorder(HttpStatusCode.OK, """{"query_status":"no_result"}""");
        var tf = new ThreatFoxProvider(new HttpClient(handler), Keys(), NullLogger<ThreatFoxProvider>.Instance);
        await tf.LookupAsync(new Indicator(IndicatorType.Hash, "44d88612fea8a8f36de82e1278abb02f"), default);
        Assert.Equal(HttpMethod.Post, handler.Request!.Method);
        Assert.Equal("https://threatfox-api.abuse.ch/api/v1/", handler.Request.RequestUri!.ToString());
        Assert.Equal("abusech-key", handler.Request.Headers.GetValues("Auth-Key").Single());
        Assert.Equal("""{"query":"search_hash","hash":"44d88612fea8a8f36de82e1278abb02f"}""", handler.Body);
    }

    // ---- URLhaus ----

    [Fact]
    public void Urlhaus_HostWithOnlineMalware()
    {
        var r = UrlhausProvider.ParseResponse(Json("""
            {"query_status":"ok","urlhaus_reference":"https://urlhaus.abuse.ch/host/bad.example/","host":"bad.example",
             "firstseen":"2026-11-01 08:00:00 UTC","url_count":"2","blacklists":{"spamhaus_dbl":"abused_legit_malware","surbl":"listed"},
             "urls":[{"url":"http://bad.example/a.exe","url_status":"online","threat":"malware_download","tags":["exe"]},
                     {"url":"http://bad.example/b.exe","url_status":"offline","threat":"malware_download","tags":null}]}
            """), IndicatorType.Domain);
        Assert.Equal(ThreatVerdict.Malicious, r.Verdict);
        Assert.Equal("2 malware URLs, 1 online", r.VendorVerdict);
        Assert.Equal("listed", r.Attributes!["Blocklist surbl"]);
    }

    [Fact]
    public void Urlhaus_OfflineOnlyIsSuspicious_AndNoResultsIsNotFound()
    {
        Assert.Equal(ThreatVerdict.Suspicious, UrlhausProvider.ParseResponse(
            Json("""{"query_status":"ok","url_count":"1","urls":[{"url":"http://x/","url_status":"offline"}]}"""), IndicatorType.Ip).Verdict);
        Assert.Equal(ThreatVerdict.NotFound,
            UrlhausProvider.ParseResponse(Json("""{"query_status":"no_results"}"""), IndicatorType.Ip).Verdict);
        // the misspelt key from URLhaus' documentation example is understood too
        Assert.Equal(ThreatVerdict.Suspicious, UrlhausProvider.ParseResponse(
            Json("""{"query_staus":"ok","url_count":"1","urls":[]}"""), IndicatorType.Ip).Verdict);
    }

    [Fact]
    public async Task Urlhaus_FormFields()
    {
        var handler = new Recorder(HttpStatusCode.OK, """{"query_status":"no_results"}""");
        var uh = new UrlhausProvider(new HttpClient(handler), Keys(), NullLogger<UrlhausProvider>.Instance);
        await uh.LookupAsync(new Indicator(IndicatorType.Hash, "44d88612fea8a8f36de82e1278abb02f"), default);
        Assert.Equal("https://urlhaus-api.abuse.ch/v1/payload/", handler.Request!.RequestUri!.ToString());
        Assert.Equal("md5_hash=44d88612fea8a8f36de82e1278abb02f", handler.Body);

        await uh.LookupAsync(new Indicator(IndicatorType.Domain, "bad-site.com"), default);
        Assert.Equal("https://urlhaus-api.abuse.ch/v1/host/", handler.Request!.RequestUri!.ToString());
        Assert.Equal("host=bad-site.com", handler.Body);

        // reserved / internal names are never sent (.example is an RFC 2606 test TLD)
        handler.Request = null;
        var skipped = await uh.LookupAsync(new Indicator(IndicatorType.Domain, "bad.example"), default);
        Assert.Null(handler.Request);
        Assert.Equal(ThreatVerdict.Skipped, skipped.Verdict);
    }

    // ---- MalwareBazaar ----

    [Fact]
    public void MalwareBazaar_KnownSample()
    {
        var r = MalwareBazaarProvider.ParseResponse(Json("""
            {"query_status":"ok","data":[{"sha256_hash":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
              "file_name":"invoice.exe","file_size":51200,"file_type":"exe","signature":"AgentTesla",
              "tags":["AgentTesla","exe"],"delivery_method":"email_attachment","first_seen":"2026-11-02 09:00:00"}]}
            """));
        Assert.Equal(ThreatVerdict.Malicious, r.Verdict);
        Assert.Equal("AgentTesla sample", r.VendorVerdict);
        Assert.Equal("email attachment", r.Attributes!["Delivery"]);
        Assert.Equal("51,200 bytes", r.Attributes["File size"]);
    }

    [Fact]
    public void MalwareBazaar_NotFound()
    {
        var r = MalwareBazaarProvider.ParseResponse(Json("""{"query_status":"hash_not_found"}"""));
        Assert.Equal(ThreatVerdict.NotFound, r.Verdict);
        Assert.Equal("Not in MalwareBazaar", r.VendorVerdict);
    }

    [Fact]
    public void MalwareBazaar_OnlyChecksHashes()
    {
        var mb = new MalwareBazaarProvider(new HttpClient(), Keys(), NullLogger<MalwareBazaarProvider>.Instance);
        Assert.True(mb.Supports(IndicatorType.Hash));
        Assert.False(mb.Supports(IndicatorType.Ip));
        Assert.False(mb.Supports(IndicatorType.Domain));
    }

    // ---- LogAnalyzer verdict ----

    private static IpReputation A(ThreatVerdict v, string provider = "x") => new() { Verdict = v, Provider = provider };

    [Fact]
    public void Consensus_NoAnswers_IsNoData()
    {
        Assert.Equal(ConsensusVerdict.NoData, ThreatConsensus.Compute([]).Verdict);
        var failed = ThreatConsensus.Compute([A(ThreatVerdict.Error), A(ThreatVerdict.Skipped)]);
        Assert.Equal(ConsensusVerdict.NoData, failed.Verdict);
        Assert.Equal(1, failed.Failed);
    }

    [Fact]
    public void Consensus_TwoMaliciousVendors_IsMalicious()
    {
        var c = ThreatConsensus.Compute([
            A(ThreatVerdict.Malicious), A(ThreatVerdict.Malicious), A(ThreatVerdict.NotFound),
            A(ThreatVerdict.NotFound), A(ThreatVerdict.Unknown), A(ThreatVerdict.NotFound),
            A(ThreatVerdict.NotFound), A(ThreatVerdict.NotFound), A(ThreatVerdict.NotFound)]);
        Assert.Equal(ConsensusVerdict.Malicious, c.Verdict);
        Assert.Equal(22, c.Score);
        Assert.Equal(9, c.Answered);
    }

    [Fact]
    public void Consensus_OneMaliciousOfMany_IsOnlySuspicious()
    {
        var c = ThreatConsensus.Compute([A(ThreatVerdict.Malicious), A(ThreatVerdict.NotFound), A(ThreatVerdict.NotFound), A(ThreatVerdict.Unknown)]);
        Assert.Equal(ConsensusVerdict.Suspicious, c.Verdict);
        Assert.Equal(25, c.Score);
    }

    [Fact]
    public void Consensus_OneMaliciousOfTwo_IsMalicious()
    {
        var c = ThreatConsensus.Compute([A(ThreatVerdict.Malicious), A(ThreatVerdict.Unknown)]);
        Assert.Equal(ConsensusVerdict.Malicious, c.Verdict);
        Assert.Equal(50, c.Score);
    }

    [Fact]
    public void Consensus_BenignVoteLowersTheScore()
    {
        // A known scanner: AbuseIPDB reports it, GreyNoise knows it as a benign research scanner.
        var c = ThreatConsensus.Compute([A(ThreatVerdict.Malicious), A(ThreatVerdict.Benign)]);
        Assert.Equal(25, c.Score);
        Assert.Equal(ConsensusVerdict.Suspicious, c.Verdict);
    }

    [Fact]
    public void Consensus_BenignOutweighingAWeakFinding_IsBenign()
    {
        // 8.8.8.8 on 2026-11-18: VirusTotal 1/92 engines (Suspicious), AbuseIPDB whitelisted (Benign).
        var c = ThreatConsensus.Compute([A(ThreatVerdict.Suspicious), A(ThreatVerdict.Benign)]);
        Assert.Equal(0, c.Score);
        Assert.Equal(ConsensusVerdict.Benign, c.Verdict);
        Assert.Contains("Mixed signals", c.Explanation);
    }

    [Theory]
    [InlineData(ThreatVerdict.Benign, ConsensusVerdict.Benign)]
    [InlineData(ThreatVerdict.NotFound, ConsensusVerdict.NoThreatFound)]
    [InlineData(ThreatVerdict.Suspicious, ConsensusVerdict.Suspicious)]
    public void Consensus_SingleAnswers(ThreatVerdict only, ConsensusVerdict expected) =>
        Assert.Equal(expected, ThreatConsensus.Compute([A(only), A(ThreatVerdict.NotFound)]).Verdict);

    [Fact]
    public void Consensus_ExplainsItself()
    {
        var c = ThreatConsensus.Compute([A(ThreatVerdict.Malicious), A(ThreatVerdict.Suspicious), A(ThreatVerdict.NotFound), A(ThreatVerdict.Error)]);
        Assert.Equal("3 provider(s) answered: 1 malicious, 1 suspicious, 1 without findings. 1 could not be reached.", c.Explanation);
        Assert.Equal(50, c.Score);
    }
}
