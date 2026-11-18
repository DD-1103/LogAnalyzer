using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using LogAnalyzer.Web.Models;
using Microsoft.Extensions.Options;

namespace LogAnalyzer.Web.Services;

// Threat-intel vendors added on 2026-11-18 (besides AbuseIPDB, GreyNoise and VirusTotal in ThreatIntel.cs).
// Request/response formats follow the vendors' public documentation (abuse.ch, GTI docs, OTX SDK);
// Recorded Future's Connect API docs need a login, so that parser follows its widely used v2 format and is
// tolerant of missing fields. Every parser is a static ParseResponse method covered by unit tests.

/// <summary>
/// Google Threat Intelligence: the VirusTotal API v3 with a GTI licence, plus Google's own "gti_assessment"
/// (verdict, severity, threat score 0-100). Enterprise only: use a personal/university licence, never a work key.
/// </summary>
public sealed class GtiProvider(HttpClient http, IOptions<EnrichmentOptions> options, ILogger<GtiProvider> logger)
    : ThreatIntelProviderBase(http, logger)
{
    public const string ProviderName = "GTI";
    private readonly EnrichmentOptions _o = options.Value;

    public override string Name => ProviderName;
    public override string Slug => "gti";
    public override string ApiKeySetting => "Enrichment:GtiApiKey";
    public override string SignupUrl => "https://cloud.google.com/security/products/threat-intelligence";
    public override string QuotaNote => "Enterprise licence; quota depends on the contract.";
    public override string Description => "Google Threat Intelligence assessment: verdict, severity and a 0–100 threat score for IPs, domains and files.";
    public override bool IsConfigured => !string.IsNullOrWhiteSpace(_o.GtiApiKey);
    public override int MaxPerRun => _o.DefaultMaxPerRun;
    public override IReadOnlyCollection<IndicatorType> SupportedTypes => [IndicatorType.Ip, IndicatorType.Domain, IndicatorType.Hash];

    public override string WebLink(string ip) => $"https://www.virustotal.com/gui/ip-address/{Uri.EscapeDataString(ip)}";
    public override string WebLink(Indicator indicator) => indicator.Type switch
    {
        IndicatorType.Domain => $"https://www.virustotal.com/gui/domain/{Uri.EscapeDataString(indicator.Value)}",
        IndicatorType.Hash => $"https://www.virustotal.com/gui/file/{Uri.EscapeDataString(indicator.Value)}",
        _ => WebLink(indicator.Value)
    };

    protected override HttpRequestMessage BuildRequest(string ip) => BuildRequest(Indicator.ForIp(ip));

    protected override HttpRequestMessage BuildRequest(Indicator indicator)
    {
        var collection = indicator.Type switch { IndicatorType.Domain => "domains", IndicatorType.Hash => "files", _ => "ip_addresses" };
        var request = new HttpRequestMessage(HttpMethod.Get,
            $"https://www.virustotal.com/api/v3/{collection}/{Uri.EscapeDataString(indicator.Value)}");
        request.Headers.Add("x-apikey", _o.GtiApiKey);
        request.Headers.Add("x-tool", "LogAnalyzer");   // required by GTI to return gti_assessment
        return request;
    }

    protected override ReputationResult? OnNotFound(JsonElement? body) =>
        new(ThreatVerdict.NotFound, "Google Threat Intelligence has no record of this indicator", VendorVerdict: "Not found");

    protected override ReputationResult Parse(JsonElement root) => ParseResponse(root);

    public static ReputationResult ParseResponse(JsonElement root)
    {
        var a = root.GetProperty("data").GetProperty("attributes");
        var attributes = new Dictionary<string, string>();

        if (!a.TryGetProperty("gti_assessment", out var g) || g.ValueKind != JsonValueKind.Object)
        {
            // GTI only assesses some indicators; fall back to the engine statistics.
            var vt = VirusTotalProvider.ParseResponse(root);
            return vt with { Summary = "No GTI assessment for this indicator. " + vt.Summary, VendorVerdict = "No GTI assessment" };
        }

        var verdictValue = Nested(g, "verdict") ?? "VERDICT_UNKNOWN";
        var severity = Nested(g, "severity") ?? "SEVERITY_UNKNOWN";
        int? threatScore = g.TryGetProperty("threat_score", out var ts) && ts.ValueKind == JsonValueKind.Object ? Int(ts, "value") : null;

        var verdict = verdictValue switch
        {
            "VERDICT_MALICIOUS" => ThreatVerdict.Malicious,
            "VERDICT_SUSPICIOUS" => ThreatVerdict.Suspicious,
            "VERDICT_BENIGN" => ThreatVerdict.Benign,
            _ => ThreatVerdict.Unknown       // VERDICT_UNDETECTED / VERDICT_UNKNOWN
        };
        var label = Pretty(verdictValue, "VERDICT_");

        AddIf(attributes, "GTI verdict", label);
        AddIf(attributes, "Severity", Pretty(severity, "SEVERITY_"));
        AddIf(attributes, "Threat score", threatScore?.ToString(CultureInfo.InvariantCulture));
        AddIf(attributes, "Assessment", Str(g, "description"));
        if (g.TryGetProperty("contributing_factors", out var cf) && cf.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in cf.EnumerateObject())
            {
                var value = p.Value.ValueKind switch
                {
                    JsonValueKind.True => "Yes",
                    JsonValueKind.False => "No",
                    JsonValueKind.Number or JsonValueKind.String => p.Value.ToString(),
                    JsonValueKind.Array => string.Join(", ", p.Value.EnumerateArray().Select(x => x.ToString()).Take(8)),
                    _ => null
                };
                AddIf(attributes, "Factor: " + Pretty(p.Name, ""), value);
            }
        }
        if (a.TryGetProperty("last_analysis_stats", out var stats) && stats.ValueKind == JsonValueKind.Object)
            AddIf(attributes, "Engines flagging it", $"{(Int(stats, "malicious") ?? 0) + (Int(stats, "suspicious") ?? 0)}");

        var vendorVerdict = threatScore is { } s ? $"{label}, threat score {s}" : label;
        return new ReputationResult(verdict, $"GTI: {label} (severity {Pretty(severity, "SEVERITY_").ToLowerInvariant()})",
            threatScore, attributes, VendorVerdict: vendorVerdict);
    }

    private static string? Nested(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Object ? Str(v, "value") : null;

    /// <summary>"VERDICT_MALICIOUS" → "Malicious", "mandiant_analyst_malicious" → "Mandiant analyst malicious".</summary>
    internal static string Pretty(string raw, string prefix)
    {
        var s = raw.StartsWith(prefix, StringComparison.Ordinal) ? raw[prefix.Length..] : raw;
        s = s.Replace('_', ' ').ToLowerInvariant();
        return s.Length == 0 ? raw : char.ToUpperInvariant(s[0]) + s[1..];
    }
}

/// <summary>
/// Recorded Future Connect API v2: a 0-99 risk score with the vendor's own criticality labels
/// (Unusual, Suspicious, Malicious, Very Malicious) and the risk rules that fired.
/// Enterprise only: use a personal/university licence, never a work key.
/// </summary>
public sealed class RecordedFutureProvider(HttpClient http, IOptions<EnrichmentOptions> options, ILogger<RecordedFutureProvider> logger)
    : ThreatIntelProviderBase(http, logger)
{
    public const string ProviderName = "Recorded Future";
    private readonly EnrichmentOptions _o = options.Value;

    public override string Name => ProviderName;
    public override string Slug => "recordedfuture";
    public override string ApiKeySetting => "Enrichment:RecordedFutureApiKey";
    public override string SignupUrl => "https://www.recordedfuture.com/";
    public override string QuotaNote => "Enterprise licence; quota depends on the contract. Response format not yet verified with a live key.";
    public override string Description => "Risk score 0–99 with criticality (Unusual → Very Malicious) and the evidence rules behind it.";
    public override bool IsConfigured => !string.IsNullOrWhiteSpace(_o.RecordedFutureApiKey);
    public override int MaxPerRun => _o.DefaultMaxPerRun;
    public override IReadOnlyCollection<IndicatorType> SupportedTypes => [IndicatorType.Ip, IndicatorType.Domain, IndicatorType.Hash];

    public override string WebLink(string ip) => WebLink(Indicator.ForIp(ip));
    public override string WebLink(Indicator indicator) =>
        $"https://app.recordedfuture.com/live/sc/entity/{Uri.EscapeDataString(EntityId(indicator))}";

    private static string EntityId(Indicator i) => i.Type switch
    {
        IndicatorType.Domain => "idn:" + i.Value,
        IndicatorType.Hash => "hash:" + i.Value,
        _ => "ip:" + i.Value
    };

    protected override HttpRequestMessage BuildRequest(string ip) => BuildRequest(Indicator.ForIp(ip));

    protected override HttpRequestMessage BuildRequest(Indicator indicator)
    {
        var kind = indicator.Type switch { IndicatorType.Domain => "domain", IndicatorType.Hash => "hash", _ => "ip" };
        var request = new HttpRequestMessage(HttpMethod.Get,
            $"https://api.recordedfuture.com/v2/{kind}/{Uri.EscapeDataString(indicator.Value)}?fields=risk,intelCard");
        request.Headers.Add("X-RFToken", _o.RecordedFutureApiKey);
        return request;
    }

    protected override ReputationResult? OnNotFound(JsonElement? body) =>
        new(ThreatVerdict.NotFound, "Recorded Future has no risk data for this indicator", VendorVerdict: "No risk");

    protected override ReputationResult Parse(JsonElement root) => ParseResponse(root);

    public static ReputationResult ParseResponse(JsonElement root)
    {
        var data = root.TryGetProperty("data", out var d) ? d : root;
        if (!data.TryGetProperty("risk", out var risk) || risk.ValueKind != JsonValueKind.Object)
            return new ReputationResult(ThreatVerdict.NotFound, "Recorded Future has no risk data for this indicator", VendorVerdict: "No risk");

        var score = Int(risk, "score") ?? 0;
        var criticality = Int(risk, "criticality") ?? 0;
        var label = Str(risk, "criticalityLabel");
        if (string.IsNullOrWhiteSpace(label) || label == "None")
            label = criticality switch { 4 => "Very Malicious", 3 => "Malicious", 2 => "Suspicious", 1 => "Unusual", _ => "No current evidence" };

        var verdict = criticality switch
        {
            >= 3 => ThreatVerdict.Malicious,
            2 => ThreatVerdict.Suspicious,
            1 => ThreatVerdict.Unknown,     // "Unusual": weak signal, not suspicious on its own
            _ => score == 0 ? ThreatVerdict.NotFound : ThreatVerdict.Unknown
        };

        var attributes = new Dictionary<string, string>();
        AddIf(attributes, "Criticality", label);
        AddIf(attributes, "Risk score", $"{score} / 99");
        AddIf(attributes, "Rules triggered", Str(risk, "riskString"));
        AddIf(attributes, "Summary", Str(risk, "riskSummary"));
        if (risk.TryGetProperty("evidenceDetails", out var evidence) && evidence.ValueKind == JsonValueKind.Array)
        {
            foreach (var e in evidence.EnumerateArray()
                         .OrderByDescending(e => Int(e, "criticality") ?? 0).Take(10))
                AddIf(attributes, $"Rule: {Str(e, "rule") ?? "unnamed"}",
                    $"{Str(e, "criticalityLabel") ?? "?"} - {Str(e, "evidenceString")}".Trim(' ', '-'));
        }
        AddIf(attributes, "Intelligence card", Str(data, "intelCard"));

        return new ReputationResult(verdict, $"Recorded Future: {label}, risk {score}", score, attributes,
            VendorVerdict: $"{label}, risk {score}");
    }
}

/// <summary>AlienVault OTX: how many community threat reports ("pulses") mention the indicator, and which malware.</summary>
public sealed class OtxProvider(HttpClient http, IOptions<EnrichmentOptions> options, ILogger<OtxProvider> logger)
    : ThreatIntelProviderBase(http, logger)
{
    public const string ProviderName = "AlienVault OTX";
    private readonly EnrichmentOptions _o = options.Value;

    public override string Name => ProviderName;
    public override string Slug => "otx";
    public override string ApiKeySetting => "Enrichment:OtxApiKey";
    public override string SignupUrl => "https://otx.alienvault.com/";
    public override string QuotaNote => "Free account; generous rate limits.";
    public override string Description => "Open Threat Exchange: community threat reports (pulses), malware families and adversaries linked to the indicator.";
    public override bool IsConfigured => !string.IsNullOrWhiteSpace(_o.OtxApiKey);
    public override int MaxPerRun => _o.DefaultMaxPerRun;
    public override IReadOnlyCollection<IndicatorType> SupportedTypes => [IndicatorType.Ip, IndicatorType.Domain, IndicatorType.Hash];

    public override string WebLink(string ip) => WebLink(Indicator.ForIp(ip));
    public override string WebLink(Indicator indicator) =>
        $"https://otx.alienvault.com/indicator/{(indicator.Type == IndicatorType.Ip ? "ip" : Section(indicator))}/{Uri.EscapeDataString(indicator.Value)}";

    private static string Section(Indicator i) => i.Type switch
    {
        IndicatorType.Domain => "domain",
        IndicatorType.Hash => "file",
        _ => i.Value.Contains(':') ? "IPv6" : "IPv4"
    };

    protected override HttpRequestMessage BuildRequest(string ip) => BuildRequest(Indicator.ForIp(ip));

    protected override HttpRequestMessage BuildRequest(Indicator indicator)
    {
        var request = new HttpRequestMessage(HttpMethod.Get,
            $"https://otx.alienvault.com/api/v1/indicators/{Section(indicator)}/{Uri.EscapeDataString(indicator.Value)}/general");
        request.Headers.Add("X-OTX-API-KEY", _o.OtxApiKey);
        return request;
    }

    protected override ReputationResult? OnNotFound(JsonElement? body) =>
        new(ThreatVerdict.NotFound, "Not in any OTX pulse", VendorVerdict: "In 0 pulses");

    protected override ReputationResult Parse(JsonElement root) => ParseResponse(root);

    public static ReputationResult ParseResponse(JsonElement root)
    {
        var count = 0;
        var pulses = new List<JsonElement>();
        if (root.TryGetProperty("pulse_info", out var info) && info.ValueKind == JsonValueKind.Object)
        {
            count = Int(info, "count") ?? 0;
            if (info.TryGetProperty("pulses", out var list) && list.ValueKind == JsonValueKind.Array)
                pulses = list.EnumerateArray().ToList();
        }

        var families = pulses
            .SelectMany(p => p.TryGetProperty("malware_families", out var m) && m.ValueKind == JsonValueKind.Array
                ? m.EnumerateArray().Select(x => x.ValueKind == JsonValueKind.Object ? Str(x, "display_name") : x.ValueKind == JsonValueKind.String ? x.GetString() : null)
                : [])
            .Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).Take(6).ToList();
        var adversaries = pulses.Select(p => Str(p, "adversary")).Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToList();
        var tags = pulses
            .SelectMany(p => p.TryGetProperty("tags", out var t) && t.ValueKind == JsonValueKind.Array
                ? t.EnumerateArray().Select(x => x.ValueKind == JsonValueKind.String ? x.GetString() : null) : [])
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .GroupBy(x => x!.ToLowerInvariant()).OrderByDescending(g => g.Count()).Take(8).Select(g => g.Key).ToList();

        // Being in community reports is a signal, not proof; malware families or many reports raise it.
        var verdict = count == 0 ? ThreatVerdict.NotFound
            : families.Count > 0 || count >= 5 ? ThreatVerdict.Malicious
            : ThreatVerdict.Suspicious;
        int? score = count == 0 ? 0 : Math.Min(100, 20 + count * 10 + families.Count * 10);

        var attributes = new Dictionary<string, string>();
        AddIf(attributes, "Pulses", count.ToString(CultureInfo.InvariantCulture));
        AddIf(attributes, "Malware families", string.Join(", ", families));
        AddIf(attributes, "Adversaries", string.Join(", ", adversaries));
        AddIf(attributes, "Common tags", string.Join(", ", tags));
        foreach (var (p, i) in pulses.Take(5).Select((p, i) => (p, i)))
            AddIf(attributes, $"Pulse {i + 1}", Str(p, "name"));
        AddIf(attributes, "Reputation", Int(root, "reputation")?.ToString(CultureInfo.InvariantCulture));
        AddIf(attributes, "Country", Str(root, "country_name"));
        AddIf(attributes, "ASN", Str(root, "asn"));
        AddIf(attributes, "Type", Str(root, "type_title"));

        var vendorVerdict = count == 1 ? "In 1 pulse" : $"In {count} pulses";
        return new ReputationResult(verdict,
            count == 0 ? "Not in any OTX pulse" : $"{vendorVerdict}{(families.Count > 0 ? ": " + string.Join(", ", families.Take(3)) : "")}",
            score, attributes, VendorVerdict: vendorVerdict);
    }
}

/// <summary>Shared by the three abuse.ch platforms: one free Auth-Key, POST requests, "query_status" answers.</summary>
public abstract class AbuseChProviderBase(HttpClient http, IOptions<EnrichmentOptions> options, ILogger logger)
    : ThreatIntelProviderBase(http, logger)
{
    protected readonly EnrichmentOptions O = options.Value;

    public override string ApiKeySetting => "Enrichment:AbuseChAuthKey";
    public override string SignupUrl => "https://auth.abuse.ch/";
    public override string QuotaNote => "Free Auth-Key for non-commercial use (one key for ThreatFox, URLhaus and MalwareBazaar).";
    public override bool IsConfigured => !string.IsNullOrWhiteSpace(O.AbuseChAuthKey);
    public override int MaxPerRun => O.DefaultMaxPerRun;

    protected HttpRequestMessage Post(string url, HttpContent content)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
        request.Headers.Add("Auth-Key", O.AbuseChAuthKey);
        return request;
    }

    protected static HttpContent Form(params (string Key, string Value)[] fields) =>
        new FormUrlEncodedContent(fields.Select(f => new KeyValuePair<string, string>(f.Key, f.Value)));

    protected static HttpContent Json(object body) =>
        new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, new MediaTypeHeaderValue("application/json"));

    /// <summary>"query_status" (URLhaus' documentation example also shows the misspelt "query_staus").</summary>
    public static string? Status(JsonElement root) => Str(root, "query_status") ?? Str(root, "query_staus");

    /// <summary>Records under "data" (array or object) or the top level itself.</summary>
    public static IEnumerable<JsonElement> Records(JsonElement root) =>
        root.TryGetProperty("data", out var data)
            ? data.ValueKind switch
            {
                JsonValueKind.Array => data.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.Object),
                JsonValueKind.Object => [data],
                _ => []
            }
            : [root];

    public static string Tags(JsonElement e) =>
        e.TryGetProperty("tags", out var t) && t.ValueKind == JsonValueKind.Array
            ? string.Join(", ", t.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()).Take(10))
            : string.Empty;
}

/// <summary>abuse.ch ThreatFox: known malware infrastructure (C2 servers, payload hosts) and the malware behind it.</summary>
public sealed class ThreatFoxProvider(HttpClient http, IOptions<EnrichmentOptions> options, ILogger<ThreatFoxProvider> logger)
    : AbuseChProviderBase(http, options, logger)
{
    public const string ProviderName = "ThreatFox";

    public override string Name => ProviderName;
    public override string Slug => "threatfox";
    public override string Description => "Indicators of compromise shared by the community: C2 servers, botnet and payload infrastructure, with malware family and confidence.";
    public override IReadOnlyCollection<IndicatorType> SupportedTypes => [IndicatorType.Ip, IndicatorType.Domain, IndicatorType.Hash];
    public override string WebLink(string ip) => $"https://threatfox.abuse.ch/browse.php?search=ioc%3A{Uri.EscapeDataString(ip)}";
    public override string WebLink(Indicator indicator) => indicator.Type == IndicatorType.Hash
        ? $"https://threatfox.abuse.ch/browse.php?search=hash%3A{Uri.EscapeDataString(indicator.Value)}"
        : WebLink(indicator.Value);

    protected override HttpRequestMessage BuildRequest(string ip) => BuildRequest(Indicator.ForIp(ip));

    protected override HttpRequestMessage BuildRequest(Indicator indicator) => Post("https://threatfox-api.abuse.ch/api/v1/",
        indicator.Type == IndicatorType.Hash
            ? Json(new { query = "search_hash", hash = indicator.Value })
            : Json(new { query = "search_ioc", search_term = indicator.Value, exact_match = false }));

    protected override ReputationResult Parse(JsonElement root) => ParseResponse(root, null);
    protected override ReputationResult Parse(JsonElement root, Indicator indicator) => ParseResponse(root, indicator);

    public static ReputationResult ParseResponse(JsonElement root, Indicator? searched)
    {
        if (Status(root) != "ok")
            return new ReputationResult(ThreatVerdict.NotFound, "Not a known indicator in ThreatFox (last 6 months)", VendorVerdict: "Not listed");

        // search_ioc is a wildcard search: keep only this IP (also "ip:port") or this domain, not 1.2.3.45 for 1.2.3.4.
        var hits = Records(root).Where(e => searched is null || searched.Type == IndicatorType.Hash || Matches(Str(e, "ioc"), searched.Value)).ToList();
        if (hits.Count == 0)
            return new ReputationResult(ThreatVerdict.NotFound, "Not a known indicator in ThreatFox (last 6 months)", VendorVerdict: "Not listed");

        var best = hits.OrderByDescending(e => Int(e, "confidence_level") ?? 0).First();
        var malware = Str(best, "malware_printable") ?? Str(best, "malware") ?? "Unknown malware";
        var confidence = Int(best, "confidence_level") ?? 0;
        var threat = Str(best, "threat_type_desc") ?? Str(best, "threat_type");

        var attributes = new Dictionary<string, string>();
        AddIf(attributes, "Malware", malware);
        AddIf(attributes, "Threat type", threat);
        AddIf(attributes, "Confidence", $"{confidence}%");
        AddIf(attributes, "Indicator", Str(best, "ioc"));
        AddIf(attributes, "Indicator type", Str(best, "ioc_type_desc") ?? Str(best, "ioc_type"));
        AddIf(attributes, "Aliases", Str(best, "malware_alias"));
        AddIf(attributes, "First seen", Str(best, "first_seen"));
        AddIf(attributes, "Last seen", Str(best, "last_seen"));
        AddIf(attributes, "Tags", Tags(best));
        AddIf(attributes, "Reporter", Str(best, "reporter"));
        AddIf(attributes, "Reference", Str(best, "reference"));
        AddIf(attributes, "Malpedia", Str(best, "malware_malpedia"));
        if (hits.Count > 1)
            AddIf(attributes, "Other entries", string.Join(", ", hits.Skip(1).Select(h => Str(h, "malware_printable")).Where(x => x is not null).Distinct().Take(6)));

        var verdict = confidence >= 50 ? ThreatVerdict.Malicious : ThreatVerdict.Suspicious;
        return new ReputationResult(verdict, $"{malware}{(threat is null ? "" : " - " + threat)} (confidence {confidence}%)",
            confidence, attributes, VendorVerdict: $"{malware}, confidence {confidence}%");
    }

    private static bool Matches(string? ioc, string value) =>
        ioc is not null && (ioc.Equals(value, StringComparison.OrdinalIgnoreCase)
                            || ioc.StartsWith(value + ":", StringComparison.OrdinalIgnoreCase)
                            || ioc.StartsWith("[" + value + "]:", StringComparison.OrdinalIgnoreCase)
                            || Uri.TryCreate(ioc, UriKind.Absolute, out var u) && u.Host.Equals(value, StringComparison.OrdinalIgnoreCase));
}

/// <summary>abuse.ch URLhaus: URLs that distribute malware, by host (IP or domain) or by payload hash.</summary>
public sealed class UrlhausProvider(HttpClient http, IOptions<EnrichmentOptions> options, ILogger<UrlhausProvider> logger)
    : AbuseChProviderBase(http, options, logger)
{
    public const string ProviderName = "URLhaus";

    public override string Name => ProviderName;
    public override string Slug => "urlhaus";
    public override string Description => "Malware distribution URLs: whether a host serves malware right now, and which files were delivered from it.";
    public override IReadOnlyCollection<IndicatorType> SupportedTypes => [IndicatorType.Ip, IndicatorType.Domain, IndicatorType.Hash];
    public override string WebLink(string ip) => $"https://urlhaus.abuse.ch/host/{Uri.EscapeDataString(ip)}/";
    public override string WebLink(Indicator indicator) => indicator.Type == IndicatorType.Hash
        ? $"https://urlhaus.abuse.ch/browse.php?search={Uri.EscapeDataString(indicator.Value)}"
        : WebLink(indicator.Value);

    protected override HttpRequestMessage BuildRequest(string ip) => BuildRequest(Indicator.ForIp(ip));

    protected override HttpRequestMessage BuildRequest(Indicator indicator) => indicator.Type == IndicatorType.Hash
        ? Post("https://urlhaus-api.abuse.ch/v1/payload/",
            Form((indicator.Value.Length == 32 ? "md5_hash" : "sha256_hash", indicator.Value)))
        : Post("https://urlhaus-api.abuse.ch/v1/host/", Form(("host", indicator.Value)));

    protected override ReputationResult Parse(JsonElement root) => ParseResponse(root, IndicatorType.Ip);
    protected override ReputationResult Parse(JsonElement root, Indicator indicator) => ParseResponse(root, indicator.Type);

    public static ReputationResult ParseResponse(JsonElement root, IndicatorType type)
    {
        var status = Status(root);
        if (status != "ok")
            return new ReputationResult(ThreatVerdict.NotFound,
                type == IndicatorType.Hash ? "URLhaus has not seen this file" : "No malware URLs known on this host",
                VendorVerdict: "Not listed");

        var urls = root.TryGetProperty("urls", out var u) && u.ValueKind == JsonValueKind.Array ? u.EnumerateArray().ToList() : [];
        var online = urls.Count(x => Str(x, "url_status") == "online");
        var total = int.TryParse(Str(root, "url_count"), out var c) ? c : Int(root, "url_count") ?? urls.Count;

        var attributes = new Dictionary<string, string>();
        AddIf(attributes, "Malware URLs", total.ToString(CultureInfo.InvariantCulture));
        AddIf(attributes, "Online now", online.ToString(CultureInfo.InvariantCulture));
        AddIf(attributes, "First seen", Str(root, "firstseen"));
        AddIf(attributes, "Last seen", Str(root, "lastseen"));
        if (type == IndicatorType.Hash)
        {
            AddIf(attributes, "Signature", Str(root, "signature"));
            AddIf(attributes, "File type", Str(root, "file_type"));
            AddIf(attributes, "File size", Str(root, "file_size") ?? Int(root, "file_size")?.ToString(CultureInfo.InvariantCulture));
        }
        if (root.TryGetProperty("blacklists", out var bl) && bl.ValueKind == JsonValueKind.Object)
            foreach (var p in bl.EnumerateObject())
                AddIf(attributes, "Blocklist " + p.Name, p.Value.ToString());
        foreach (var (x, i) in urls.Take(5).Select((x, i) => (x, i)))
            AddIf(attributes, $"URL {i + 1}", $"{Str(x, "url")} ({Str(x, "url_status")}{(Str(x, "threat") is { } t ? ", " + t : "")})");
        AddIf(attributes, "Tags", string.Join(", ", urls.Select(Tags).Where(t => t.Length > 0).Distinct().Take(5)));

        var verdict = type == IndicatorType.Hash || online > 0 ? ThreatVerdict.Malicious
            : total > 0 ? ThreatVerdict.Suspicious : ThreatVerdict.NotFound;
        var signature = Str(root, "signature");
        var vendorVerdict = type == IndicatorType.Hash
            ? $"Malware payload{(signature is null ? "" : ": " + signature)}"
            : $"{total} malware URL{(total == 1 ? "" : "s")}, {online} online";
        return new ReputationResult(verdict, vendorVerdict, online > 0 ? 100 : total > 0 ? 60 : 0, attributes, VendorVerdict: vendorVerdict);
    }
}

/// <summary>abuse.ch MalwareBazaar: confirmed malware samples by hash, with family, delivery method and tags.</summary>
public sealed class MalwareBazaarProvider(HttpClient http, IOptions<EnrichmentOptions> options, ILogger<MalwareBazaarProvider> logger)
    : AbuseChProviderBase(http, options, logger)
{
    public const string ProviderName = "MalwareBazaar";

    public override string Name => ProviderName;
    public override string Slug => "malwarebazaar";
    public override string Description => "Repository of confirmed malware samples: tells whether a file hash is known malware and which family.";
    public override IReadOnlyCollection<IndicatorType> SupportedTypes => [IndicatorType.Hash];
    public override string WebLink(string ip) => "https://bazaar.abuse.ch/";
    public override string WebLink(Indicator indicator) =>
        $"https://bazaar.abuse.ch/browse.php?search={Uri.EscapeDataString((indicator.Value.Length switch { 32 => "md5:", 40 => "sha1:", _ => "sha256:" }) + indicator.Value)}";

    protected override HttpRequestMessage BuildRequest(string ip) => BuildRequest(Indicator.ForIp(ip));

    protected override HttpRequestMessage BuildRequest(Indicator indicator) =>
        Post("https://mb-api.abuse.ch/api/v1/", Form(("query", "get_info"), ("hash", indicator.Value)));

    protected override ReputationResult Parse(JsonElement root) => ParseResponse(root);

    public static ReputationResult ParseResponse(JsonElement root)
    {
        if (Status(root) != "ok")
            return new ReputationResult(ThreatVerdict.NotFound, "Not a known malware sample in MalwareBazaar", VendorVerdict: "Not in MalwareBazaar");

        var s = Records(root).FirstOrDefault();
        if (s.ValueKind != JsonValueKind.Object)
            return new ReputationResult(ThreatVerdict.NotFound, "Not a known malware sample in MalwareBazaar", VendorVerdict: "Not in MalwareBazaar");

        var signature = Str(s, "signature");
        var attributes = new Dictionary<string, string>();
        AddIf(attributes, "Malware family", signature);
        AddIf(attributes, "File name", Str(s, "file_name"));
        AddIf(attributes, "File type", Str(s, "file_type") ?? Str(s, "file_type_mime"));
        AddIf(attributes, "File size", Long(s, "file_size")?.ToString("N0", CultureInfo.InvariantCulture) is { } size ? size + " bytes" : null);
        AddIf(attributes, "Delivery", Str(s, "delivery_method")?.Replace('_', ' '));
        AddIf(attributes, "First seen", Str(s, "first_seen"));
        AddIf(attributes, "Last seen", Str(s, "last_seen"));
        AddIf(attributes, "Tags", Tags(s));
        AddIf(attributes, "Reporter", Str(s, "reporter"));
        AddIf(attributes, "Origin country", Str(s, "origin_country"));
        AddIf(attributes, "SHA-256", Str(s, "sha256_hash"));
        AddIf(attributes, "Imphash", Str(s, "imphash"));

        var label = signature is null ? "Known malware sample" : $"{signature} sample";
        return new ReputationResult(ThreatVerdict.Malicious, label, 100, attributes, VendorVerdict: label);
    }
}
