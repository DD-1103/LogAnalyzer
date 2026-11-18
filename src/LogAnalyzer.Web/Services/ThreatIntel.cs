using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace LogAnalyzer.Web.Services;

/// <summary>Settings of the "Enrichment" configuration section. API keys belong in user-secrets.</summary>
public sealed class EnrichmentOptions
{
    public const string Section = "Enrichment";

    public string? GeoLiteCityDb { get; set; }

    public string? AbuseIpDbApiKey { get; set; }
    public string? GreyNoiseApiKey { get; set; }
    public string? VirusTotalApiKey { get; set; }

    /// <summary>How long a provider answer is reused before the IP is looked up again.</summary>
    public int CacheDays { get; set; } = 7;

    // Free-tier friendly limits for the automatic lookups after each log file.
    public int AbuseIpDbMaxPerRun { get; set; } = 200;   // free: 1,000 checks/day
    public int GreyNoiseMaxPerRun { get; set; } = 25;    // community: small daily quota
    public int VirusTotalMaxPerRun { get; set; } = 4;    // public API: 4 requests/min, 500/day
    public int VirusTotalMinIntervalSeconds { get; set; } = 15;

    /// <summary>Lower the severity of alerts whose source IP GreyNoise classifies as benign (RQ: alert fatigue).</summary>
    public bool GreyNoiseDowngradeBenign { get; set; } = true;

    /// <summary>
    /// Look up the attacker IPs of every processed file automatically. Off by default (privacy: client addresses
    /// only leave the machine when an analyst asks for it); turn on for the threat-intel evaluation.
    /// </summary>
    public bool AutoLookup { get; set; }

    /// <summary>
    /// The organisation's own domains (e.g. "example.org"): they and their sub-domains are never sent to providers,
    /// like private IP addresses. Built-in internal names (.local, .internal, .lan, ...) are always blocked.
    /// </summary>
    public string[] InternalDomains { get; set; } = [];

    /// <summary>Threat-intel answers and GeoIP rows of IPs without alerts are deleted after this many days.</summary>
    public int RetentionDays { get; set; } = 90;

    // Lookups per provider and UTC day (automatic + manual), below the free quotas. 0 = no limit.
    public int AbuseIpDbDailyBudget { get; set; } = 900;   // free: 1,000/day
    public int GreyNoiseDailyBudget { get; set; } = 50;    // community: small quota
    public int VirusTotalDailyBudget { get; set; } = 450;  // public API: 500/day

    public int DailyBudget(string provider) => provider switch
    {
        AbuseIpDbProvider.ProviderName => AbuseIpDbDailyBudget,
        GreyNoiseProvider.ProviderName => GreyNoiseDailyBudget,
        VirusTotalProvider.ProviderName => VirusTotalDailyBudget,
        _ => 0
    };
}

/// <summary>What a provider says about one IP, already mapped to the common verdict scale.</summary>
public sealed record ReputationResult(
    ThreatVerdict Verdict,
    string Summary,
    int? Score = null,
    IReadOnlyDictionary<string, string>? Attributes = null,
    string? Error = null)
{
    public static ReputationResult Failed(string error) => new(ThreatVerdict.Error, error, Error: error);
    public static ReputationResult Skipped(string reason) => new(ThreatVerdict.Skipped, reason);
}

/// <summary>One threat-intelligence source. New vendors only need a new implementation + DI registration.</summary>
public interface IThreatIntelProvider
{
    /// <summary>Display name, also stored in <see cref="IpReputation.Provider"/>.</summary>
    string Name { get; }

    /// <summary>URL-friendly id used in routes: /ThreatIntel/Provider/{slug}.</summary>
    string Slug { get; }

    /// <summary>Configuration key of the API key (set with dotnet user-secrets).</summary>
    string ApiKeySetting { get; }

    string SignupUrl { get; }
    string QuotaNote { get; }
    string Description { get; }
    bool IsConfigured { get; }
    int MaxPerRun { get; }
    TimeSpan MinInterval { get; }

    /// <summary>Link to the provider's own web page for an IP (built by us, never taken from API output).</summary>
    string WebLink(string ip);

    Task<ReputationResult> LookupAsync(string ip, CancellationToken ct);

    /// <summary>Indicator types this provider can look up (IP only unless the provider says otherwise).</summary>
    IReadOnlyCollection<IndicatorType> SupportedTypes => [IndicatorType.Ip];

    bool Supports(IndicatorType type) => SupportedTypes.Contains(type);

    string WebLink(Indicator indicator) => WebLink(indicator.Value);

    Task<ReputationResult> LookupAsync(Indicator indicator, CancellationToken ct) =>
        indicator.Type == IndicatorType.Ip
            ? LookupAsync(indicator.Value, ct)
            : Task.FromResult(ReputationResult.Skipped($"{Name} does not look up {indicator.Label.ToLowerInvariant()}s"));
}

/// <summary>Shared HTTP handling: status codes, timeouts, JSON errors. Subclasses build the request and parse the body.</summary>
public abstract class ThreatIntelProviderBase(HttpClient http, ILogger logger) : IThreatIntelProvider
{
    public abstract string Name { get; }
    public abstract string Slug { get; }
    public abstract string ApiKeySetting { get; }
    public abstract string SignupUrl { get; }
    public abstract string QuotaNote { get; }
    public abstract string Description { get; }
    public abstract bool IsConfigured { get; }
    public abstract int MaxPerRun { get; }
    public virtual TimeSpan MinInterval => TimeSpan.Zero;
    public abstract string WebLink(string ip);
    public virtual string WebLink(Indicator indicator) => WebLink(indicator.Value);

    public virtual IReadOnlyCollection<IndicatorType> SupportedTypes => [IndicatorType.Ip];
    public bool Supports(IndicatorType type) => SupportedTypes.Contains(type);

    protected abstract HttpRequestMessage BuildRequest(string ip);

    /// <summary>Request for any supported indicator type; IP-only providers keep using <see cref="BuildRequest(string)"/>.</summary>
    protected virtual HttpRequestMessage BuildRequest(Indicator indicator) => BuildRequest(indicator.Value);

    /// <summary>Called for HTTP 404: some providers use it for "no data about this IP".</summary>
    protected virtual ReputationResult? OnNotFound(JsonElement? body) => null;
    protected virtual ReputationResult? OnNotFound(JsonElement? body, Indicator indicator) => OnNotFound(body);

    protected abstract ReputationResult Parse(JsonElement root);
    protected virtual ReputationResult Parse(JsonElement root, Indicator indicator) => Parse(root);

    public Task<ReputationResult> LookupAsync(string ip, CancellationToken ct) => LookupAsync(Indicator.ForIp(ip), ct);

    public async Task<ReputationResult> LookupAsync(Indicator indicator, CancellationToken ct)
    {
        if (!IsConfigured)
            return ReputationResult.Skipped($"Not configured (set {ApiKeySetting})");
        if (!Supports(indicator.Type))
            return ReputationResult.Skipped($"{Name} does not look up {indicator.Label.ToLowerInvariant()}s");
        // Only the canonical form of a public address leaves the machine (e.g. "::ffff:8.8.8.8" is sent as "8.8.8.8");
        // internal host names never do.
        var canonical = indicator;
        if (indicator.Type == IndicatorType.Ip)
        {
            if (!IpAddressPolicy.TryGetPublic(indicator.Value, out var ip))
                return ReputationResult.Skipped("Private or reserved address - never sent to external services");
            canonical = Indicator.ForIp(ip);
        }
        else if (!IndicatorParser.MaySend(indicator, null, out var reason))
        {
            return ReputationResult.Skipped(reason);
        }
        var ipForLog = canonical.Value;

        try
        {
            using var request = BuildRequest(canonical);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var response = await http.SendAsync(request, ct);
            var body = await response.Content.ReadAsStringAsync(ct);

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                JsonElement? root = null;
                if (!string.IsNullOrWhiteSpace(body))
                {
                    try
                    {
                        using var notFoundDoc = JsonDocument.Parse(body);
                        root = notFoundDoc.RootElement.Clone();
                    }
                    catch (JsonException) { /* not JSON */ }
                }
                if (OnNotFound(root, canonical) is { } notFound)
                    return notFound;
            }

            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("{Provider} returned HTTP {Status} for {Indicator}", Name, (int)response.StatusCode, ipForLog);
                return ReputationResult.Failed(DescribeStatus(response.StatusCode));
            }

            using var doc = JsonDocument.Parse(body);
            return Parse(doc.RootElement, canonical);
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or KeyNotFoundException
                                       or InvalidOperationException or FormatException
                                   || (ex is TaskCanceledException && !ct.IsCancellationRequested))
        {
            logger.LogWarning(ex, "{Provider} lookup failed for {Indicator}", Name, ipForLog);
            return ReputationResult.Failed(ex is TaskCanceledException ? "Timeout" : $"Lookup failed: {ex.GetType().Name}");
        }
    }

    private static string DescribeStatus(HttpStatusCode code) => code switch
    {
        HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => $"API key rejected (HTTP {(int)code})",
        HttpStatusCode.TooManyRequests => "Rate limit or daily quota exceeded (HTTP 429)",
        HttpStatusCode.NotFound => "Not found (HTTP 404)",
        _ when (int)code >= 500 => $"Provider unavailable (HTTP {(int)code})",
        _ => $"Unexpected response (HTTP {(int)code})"
    };

    // ---- small JSON helpers (missing or null properties are tolerated) ----
    protected static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    protected static int? Int(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i) ? i : null;

    protected static long? Long(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var i) ? i : null;

    protected static bool? Bool(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind is JsonValueKind.True or JsonValueKind.False ? v.GetBoolean() : null;

    protected static string YesNo(bool? value) => value switch { true => "Yes", false => "No", _ => "—" };

    protected static void AddIf(Dictionary<string, string> d, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
            d[key] = value;
    }
}

/// <summary>AbuseIPDB v2 "check" endpoint: crowd-sourced abuse reports and a 0-100 confidence score.</summary>
public sealed class AbuseIpDbProvider(HttpClient http, IOptions<EnrichmentOptions> options, ILogger<AbuseIpDbProvider> logger)
    : ThreatIntelProviderBase(http, logger)
{
    public const string ProviderName = "AbuseIPDB";
    private readonly EnrichmentOptions _o = options.Value;

    public override string Name => ProviderName;
    public override string Slug => "abuseipdb";
    public override string ApiKeySetting => "Enrichment:AbuseIpDbApiKey";
    public override string SignupUrl => "https://www.abuseipdb.com/register";
    public override string QuotaNote => "Free plan: 1,000 checks per day.";
    public override string Description => "Crowd-sourced reports of abusive IPs (brute force, scanning, spam) with a 0–100 confidence score.";
    public override bool IsConfigured => !string.IsNullOrWhiteSpace(_o.AbuseIpDbApiKey);
    public override int MaxPerRun => _o.AbuseIpDbMaxPerRun;
    public override string WebLink(string ip) => $"https://www.abuseipdb.com/check/{Uri.EscapeDataString(ip)}";

    protected override HttpRequestMessage BuildRequest(string ip)
    {
        var request = new HttpRequestMessage(HttpMethod.Get,
            $"https://api.abuseipdb.com/api/v2/check?ipAddress={Uri.EscapeDataString(ip)}&maxAgeInDays=90");
        request.Headers.Add("Key", _o.AbuseIpDbApiKey);
        return request;
    }

    protected override ReputationResult Parse(JsonElement root) => ParseResponse(root);

    public static ReputationResult ParseResponse(JsonElement root)
    {
        var d = root.GetProperty("data");
        var score = d.GetProperty("abuseConfidenceScore").GetInt32();
        var reports = Int(d, "totalReports") ?? 0;
        var users = Int(d, "numDistinctUsers") ?? 0;
        var whitelisted = Bool(d, "isWhitelisted") == true;

        var verdict = whitelisted ? ThreatVerdict.Benign
            : score >= 75 ? ThreatVerdict.Malicious
            : score >= 25 ? ThreatVerdict.Suspicious
            : reports == 0 ? ThreatVerdict.NotFound
            : ThreatVerdict.Unknown;

        var attributes = new Dictionary<string, string>();
        AddIf(attributes, "Confidence score", $"{score}%");
        AddIf(attributes, "Total reports (90 days)", reports.ToString(CultureInfo.InvariantCulture));
        AddIf(attributes, "Distinct reporters", users.ToString(CultureInfo.InvariantCulture));
        AddIf(attributes, "ISP", Str(d, "isp"));
        AddIf(attributes, "Usage type", Str(d, "usageType"));
        AddIf(attributes, "Domain", Str(d, "domain"));
        AddIf(attributes, "Country", Str(d, "countryCode"));
        AddIf(attributes, "Tor exit node", YesNo(Bool(d, "isTor")));
        AddIf(attributes, "Whitelisted", YesNo(Bool(d, "isWhitelisted")));
        AddIf(attributes, "Last reported", Str(d, "lastReportedAt"));

        return new ReputationResult(verdict,
            $"Abuse confidence {score}% · {reports} report(s) from {users} user(s)",
            score, attributes);
    }
}

/// <summary>
/// GreyNoise Community API: tells whether an IP is internet background noise (mass scanner) and whether
/// that scanner is benign (search engines, research projects) or malicious. RIOT = common business services.
/// </summary>
public sealed class GreyNoiseProvider(HttpClient http, IOptions<EnrichmentOptions> options, ILogger<GreyNoiseProvider> logger)
    : ThreatIntelProviderBase(http, logger)
{
    public const string ProviderName = "GreyNoise";
    private readonly EnrichmentOptions _o = options.Value;

    public override string Name => ProviderName;
    public override string Slug => "greynoise";
    public override string ApiKeySetting => "Enrichment:GreyNoiseApiKey";
    public override string SignupUrl => "https://viz.greynoise.io/signup";
    public override string QuotaNote => "Community API: limited lookups per day/week on the free plan.";
    public override string Description => "Separates targeted attacks from internet-wide background scanning; benign scanners lower alert severity.";
    public override bool IsConfigured => !string.IsNullOrWhiteSpace(_o.GreyNoiseApiKey);
    public override int MaxPerRun => _o.GreyNoiseMaxPerRun;
    public override string WebLink(string ip) => $"https://viz.greynoise.io/ip/{Uri.EscapeDataString(ip)}";

    protected override HttpRequestMessage BuildRequest(string ip)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, $"https://api.greynoise.io/v3/community/{Uri.EscapeDataString(ip)}");
        request.Headers.Add("key", _o.GreyNoiseApiKey);
        return request;
    }

    // 404 = "IP not observed scanning the internet or contained in RIOT data set."
    protected override ReputationResult? OnNotFound(JsonElement? body) =>
        new(ThreatVerdict.NotFound, "Not observed scanning the internet (not background noise) - activity may be targeted",
            Attributes: new Dictionary<string, string> { ["Noise"] = "No", ["RIOT"] = "No" });

    protected override ReputationResult Parse(JsonElement root) => ParseResponse(root);

    public static ReputationResult ParseResponse(JsonElement root)
    {
        var noise = Bool(root, "noise") == true;
        var riot = Bool(root, "riot") == true;
        var classification = Str(root, "classification")?.ToLowerInvariant();
        var name = Str(root, "name");

        var verdict = riot ? ThreatVerdict.Benign
            : classification switch
            {
                "benign" => ThreatVerdict.Benign,
                "malicious" => ThreatVerdict.Malicious,
                _ when noise => ThreatVerdict.Suspicious,
                _ => ThreatVerdict.Unknown
            };

        var summary = riot
            ? $"Known business service (RIOT){(string.IsNullOrEmpty(name) || name == "unknown" ? "" : ": " + name)}"
            : noise
                ? $"Internet scanner, classified {classification ?? "unknown"}{(string.IsNullOrEmpty(name) || name == "unknown" ? "" : " (" + name + ")")}"
                : $"Classification: {classification ?? "unknown"}";

        var attributes = new Dictionary<string, string>();
        AddIf(attributes, "Classification", classification);
        AddIf(attributes, "Noise (mass scanner)", YesNo(noise));
        AddIf(attributes, "RIOT (business service)", YesNo(riot));
        AddIf(attributes, "Actor / service", name);
        AddIf(attributes, "Last seen", Str(root, "last_seen"));

        return new ReputationResult(verdict, summary, null, attributes);
    }
}

/// <summary>VirusTotal API v3: verdicts of ~90 security vendors for an IP address, a domain or a file hash.</summary>
public sealed class VirusTotalProvider(HttpClient http, IOptions<EnrichmentOptions> options, ILogger<VirusTotalProvider> logger)
    : ThreatIntelProviderBase(http, logger)
{
    public const string ProviderName = "VirusTotal";
    private readonly EnrichmentOptions _o = options.Value;

    public override string Name => ProviderName;
    public override string Slug => "virustotal";
    public override string ApiKeySetting => "Enrichment:VirusTotalApiKey";
    public override string SignupUrl => "https://www.virustotal.com/gui/join-us";
    public override string QuotaNote => "Public API: 4 requests/minute, 500/day (lookups are spaced automatically).";
    public override string Description => "Multi-vendor verdict: how many antivirus / URL-reputation engines flag the IP, domain or file.";
    public override bool IsConfigured => !string.IsNullOrWhiteSpace(_o.VirusTotalApiKey);
    public override int MaxPerRun => _o.VirusTotalMaxPerRun;
    public override TimeSpan MinInterval => TimeSpan.FromSeconds(Math.Max(0, _o.VirusTotalMinIntervalSeconds));
    public override string WebLink(string ip) => $"https://www.virustotal.com/gui/ip-address/{Uri.EscapeDataString(ip)}";
    public override IReadOnlyCollection<IndicatorType> SupportedTypes => [IndicatorType.Ip, IndicatorType.Domain, IndicatorType.Hash];

    public override string WebLink(Indicator indicator) => indicator.Type switch
    {
        IndicatorType.Domain => $"https://www.virustotal.com/gui/domain/{Uri.EscapeDataString(indicator.Value)}",
        IndicatorType.Hash => $"https://www.virustotal.com/gui/file/{Uri.EscapeDataString(indicator.Value)}",
        _ => WebLink(indicator.Value)
    };

    protected override HttpRequestMessage BuildRequest(string ip) => BuildRequest(Indicator.ForIp(ip));

    protected override HttpRequestMessage BuildRequest(Indicator indicator)
    {
        var collection = indicator.Type switch
        {
            IndicatorType.Domain => "domains",
            IndicatorType.Hash => "files",
            _ => "ip_addresses"
        };
        var request = new HttpRequestMessage(HttpMethod.Get,
            $"https://www.virustotal.com/api/v3/{collection}/{Uri.EscapeDataString(indicator.Value)}");
        request.Headers.Add("x-apikey", _o.VirusTotalApiKey);
        return request;
    }

    protected override ReputationResult? OnNotFound(JsonElement? body, Indicator indicator) =>
        new(ThreatVerdict.NotFound, indicator.Type switch
        {
            IndicatorType.Domain => "No VirusTotal record for this domain",
            IndicatorType.Hash => "VirusTotal has never seen this file",
            _ => "No VirusTotal record for this IP"
        });

    protected override ReputationResult Parse(JsonElement root) => ParseResponse(root);
    protected override ReputationResult Parse(JsonElement root, Indicator indicator) => ParseResponse(root, indicator.Type);

    public static ReputationResult ParseResponse(JsonElement root) => ParseResponse(root, IndicatorType.Ip);

    public static ReputationResult ParseResponse(JsonElement root, IndicatorType type)
    {
        var a = root.GetProperty("data").GetProperty("attributes");
        var stats = a.GetProperty("last_analysis_stats");
        var malicious = Int(stats, "malicious") ?? 0;
        var suspicious = Int(stats, "suspicious") ?? 0;
        var harmless = Int(stats, "harmless") ?? 0;
        var undetected = Int(stats, "undetected") ?? 0;
        var timeout = Int(stats, "timeout") ?? 0;
        var engines = malicious + suspicious + harmless + undetected + timeout;
        var reputation = Int(a, "reputation");

        var verdict = malicious >= 3 ? ThreatVerdict.Malicious
            : malicious + suspicious >= 1 ? ThreatVerdict.Suspicious
            : engines == 0 ? ThreatVerdict.NotFound
            : ThreatVerdict.Unknown;   // no engine flags it - "clean" is not proof of benign
        int? score = engines == 0 ? null : (int)Math.Round(100.0 * (malicious + suspicious) / engines);

        var attributes = new Dictionary<string, string>();
        AddIf(attributes, "Malicious", malicious.ToString(CultureInfo.InvariantCulture));
        AddIf(attributes, "Suspicious", suspicious.ToString(CultureInfo.InvariantCulture));
        AddIf(attributes, "Harmless", harmless.ToString(CultureInfo.InvariantCulture));
        AddIf(attributes, "Undetected", undetected.ToString(CultureInfo.InvariantCulture));
        AddIf(attributes, "Community reputation", reputation?.ToString(CultureInfo.InvariantCulture));
        if (type == IndicatorType.Ip)
        {
            AddIf(attributes, "AS owner", Str(a, "as_owner"));
            AddIf(attributes, "ASN", Long(a, "asn")?.ToString(CultureInfo.InvariantCulture));
            AddIf(attributes, "Network", Str(a, "network"));
            AddIf(attributes, "Country", Str(a, "country"));
        }
        else if (type == IndicatorType.Domain)
        {
            AddIf(attributes, "Registrar", Str(a, "registrar"));
            if (Long(a, "creation_date") is long created)
                attributes["Registered"] = DateTimeOffset.FromUnixTimeSeconds(created).UtcDateTime.ToString("yyyy-MM-dd");
            if (a.TryGetProperty("categories", out var cats) && cats.ValueKind == JsonValueKind.Object)
                AddIf(attributes, "Categories", string.Join(", ", cats.EnumerateObject()
                    .Select(c => c.Value.ValueKind == JsonValueKind.String ? c.Value.GetString() : null)
                    .Where(c => !string.IsNullOrWhiteSpace(c)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4)));
        }
        else
        {
            AddIf(attributes, "File name", Str(a, "meaningful_name"));
            AddIf(attributes, "File type", Str(a, "type_description"));
            if (Long(a, "size") is long size)
                attributes["Size"] = size.ToString("N0", CultureInfo.InvariantCulture) + " bytes";
            if (a.TryGetProperty("popular_threat_classification", out var ptc) && ptc.ValueKind == JsonValueKind.Object)
                AddIf(attributes, "Threat label", Str(ptc, "suggested_threat_label"));
            AddIf(attributes, "SHA-256", Str(a, "sha256"));
        }
        if (Long(a, "last_analysis_date") is long unix)
            attributes["Last analysis"] = DateTimeOffset.FromUnixTimeSeconds(unix).UtcDateTime.ToString("yyyy-MM-dd HH:mm 'UTC'");

        return new ReputationResult(verdict,
            $"{malicious} malicious / {suspicious} suspicious of {engines} engines",
            score, attributes);
    }
}

/// <summary>Keeps a minimum gap between calls to rate-limited providers (shared by the worker and the UI).</summary>
public sealed class ProviderThrottle
{
    private readonly ConcurrentDictionary<string, DateTime> _lastCall = new();
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _gates = new();

    /// <summary>
    /// Waits for (or, when <paramref name="wait"/> is false, checks) the provider's next free slot.
    /// Returns false when the caller would have to wait and chose not to.
    /// </summary>
    public async Task<bool> TryEnterAsync(string provider, TimeSpan minInterval, bool wait, CancellationToken ct)
    {
        if (minInterval <= TimeSpan.Zero)
            return true;

        var gate = _gates.GetOrAdd(provider, _ => new SemaphoreSlim(1, 1));
        if (wait)
            await gate.WaitAsync(ct);
        else if (!await gate.WaitAsync(0, ct))
            return false;

        try
        {
            var due = _lastCall.GetValueOrDefault(provider, DateTime.MinValue) + minInterval - DateTime.UtcNow;
            if (due > TimeSpan.Zero)
            {
                if (!wait)
                    return false;
                await Task.Delay(due, ct);
            }
            _lastCall[provider] = DateTime.UtcNow;
            return true;
        }
        finally
        {
            gate.Release();
        }
    }

    private readonly Dictionary<string, (DateOnly Day, int Count)> _daily = [];

    /// <summary>Counts one lookup against the provider's daily budget; false when today's budget is used up.</summary>
    public bool TryConsumeDaily(string provider, int budget)
    {
        if (budget <= 0)
            return true;
        lock (_daily)
        {
            var today = DateOnly.FromDateTime(DateTime.UtcNow);
            var (day, count) = _daily.GetValueOrDefault(provider);
            if (day != today)
                count = 0;
            if (count >= budget)
                return false;
            _daily[provider] = (today, count + 1);
            return true;
        }
    }

    public TimeSpan RetryAfter(string provider, TimeSpan minInterval)
    {
        var due = _lastCall.GetValueOrDefault(provider, DateTime.MinValue) + minInterval - DateTime.UtcNow;
        return due > TimeSpan.Zero ? due : TimeSpan.Zero;
    }
}

public sealed record ThreatIntelRunSummary(int Lookups, int Downgraded);

/// <summary>The threat-intel step for one processed log file (run by <see cref="ThreatIntelWorker"/>).</summary>
public interface ILogFileThreatIntel
{
    Task<ThreatIntelRunSummary> RunForLogFileAsync(int logFileId, CancellationToken ct);
}

/// <summary>Looks IPs up at every configured provider, caches the answers in IpReputations and applies the GreyNoise rule.</summary>
public sealed class ThreatIntelService(
    AppDbContext db,
    IEnumerable<IThreatIntelProvider> providers,
    ProviderThrottle throttle,
    IOptions<EnrichmentOptions> options,
    ILogger<ThreatIntelService> logger) : ILogFileThreatIntel
{
    private readonly EnrichmentOptions _o = options.Value;

    public IReadOnlyList<IThreatIntelProvider> Providers { get; } = providers.ToList();

    public IReadOnlyList<string> InternalDomains => _o.InternalDomains;

    public IThreatIntelProvider? Find(string? slug) =>
        Providers.FirstOrDefault(p => string.Equals(p.Slug, slug, StringComparison.OrdinalIgnoreCase));

    public Task<List<IpReputation>> GetCachedAsync(string ip, CancellationToken ct = default) =>
        db.IpReputations.AsNoTracking().Where(r => r.Ip == ip).ToListAsync(ct);

    /// <summary>
    /// Live lookup of one IP at one provider; the result replaces the cached row.
    /// With <paramref name="waitForSlot"/> false (UI requests) a throttled provider answers "try again in N s" instead of blocking.
    /// </summary>
    public Task<IpReputation> RefreshAsync(string ip, IThreatIntelProvider provider, bool waitForSlot, CancellationToken ct) =>
        RefreshAsync(Indicator.ForIp(ip), provider, waitForSlot, ct);

    /// <summary>Live lookup of one indicator (IP, domain or hash) at one provider; the answer is cached.</summary>
    /// <param name="maxWait">How long a UI request may wait for a rate-limited provider's next slot (instead of failing at once).</param>
    public async Task<IpReputation> RefreshAsync(Indicator indicator, IThreatIntelProvider provider, bool waitForSlot,
        CancellationToken ct, TimeSpan? maxWait = null)
    {
        var ip = indicator.Value;
        ReputationResult result;
        if (!provider.IsConfigured)
            result = ReputationResult.Skipped($"Not configured (set {provider.ApiKeySetting})");
        else if (!provider.Supports(indicator.Type))
            result = ReputationResult.Skipped($"{provider.Name} does not look up {indicator.Label.ToLowerInvariant()}s");
        else if (!IndicatorParser.MaySend(indicator, _o.InternalDomains, out var reason))
            result = ReputationResult.Skipped(reason);
        else if (!throttle.TryConsumeDaily(provider.Name, _o.DailyBudget(provider.Name)))
            result = ReputationResult.Failed($"Daily budget of {_o.DailyBudget(provider.Name)} lookups used up (protects the free quota); try again tomorrow");
        else if (!await EnterSlotAsync(provider, waitForSlot, maxWait, ct))
            result = ReputationResult.Failed(
                $"Rate limit: try again in {Math.Ceiling(throttle.RetryAfter(provider.Name, provider.MinInterval).TotalSeconds)} s");
        else
            result = await provider.LookupAsync(indicator, ct);

        // Two lookups of a new IP at the same time (worker + UI, or a double click) both try to insert the row:
        // the loser gets a unique-key violation, reloads the winner's row and applies its result to it.
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                var row = await ApplyResultAsync(ip, provider, result, ct);
                row.Kind = indicator.Type;
                await db.SaveChangesAsync(ct);
                return row;
            }
            catch (DbUpdateException ex) when (attempt == 1 && IsUniqueViolation(ex))
            {
                db.ChangeTracker.Clear();
            }
        }
    }

    private async Task<bool> EnterSlotAsync(IThreatIntelProvider provider, bool waitForSlot, TimeSpan? maxWait, CancellationToken ct)
    {
        if (maxWait is not { } limit || waitForSlot)
            return await throttle.TryEnterAsync(provider.Name, provider.MinInterval, waitForSlot, ct);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(limit);
        try
        {
            return await throttle.TryEnterAsync(provider.Name, provider.MinInterval, wait: true, timeout.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return false;
        }
    }

    /// <summary>
    /// What an analyst gets when pressing "Look up": every configured provider that supports the indicator type answers.
    /// Fresh cached answers (younger than CacheDays) are reused, everything else is looked up live; a rate-limited
    /// provider is waited for up to <paramref name="maxWait"/>. Unconfigured or unsupported providers are not called.
    /// </summary>
    public async Task<List<IpReputation>> LookupEverywhereAsync(Indicator indicator, TimeSpan maxWait, CancellationToken ct)
    {
        var freshAfter = DateTime.UtcNow.AddDays(-Math.Max(0, _o.CacheDays));
        var cached = (await GetCachedAsync(indicator.Value, ct)).ToDictionary(r => r.Provider);
        var results = new List<IpReputation>();
        foreach (var provider in Providers.Where(p => p.IsConfigured && p.Supports(indicator.Type)))
        {
            if (cached.TryGetValue(provider.Name, out var row) && row.HasVerdict && row.CheckedAt > freshAfter)
            {
                results.Add(row);
                continue;
            }
            results.Add(await RefreshAsync(indicator, provider, waitForSlot: false, ct, maxWait));
        }
        return results;
    }

    /// <summary>
    /// Stores a provider answer. A failed or skipped lookup never replaces an earlier real verdict (that would turn
    /// "Malicious 12/90" into "Error: rate limit" on a double click); it is recorded as the last attempt instead.
    /// </summary>
    private async Task<IpReputation> ApplyResultAsync(string ip, IThreatIntelProvider provider, ReputationResult result, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var row = await db.IpReputations.FirstOrDefaultAsync(r => r.Ip == ip && r.Provider == provider.Name, ct);
        var failed = result.Verdict is ThreatVerdict.Error or ThreatVerdict.Skipped;
        if (row is not null && row.HasVerdict && failed)
        {
            row.LastAttemptAt = now;
            row.LastAttemptError = Cut(result.Error ?? result.Summary, 500);
            return row;
        }

        if (row is null)
        {
            row = new IpReputation { Ip = ip, Provider = provider.Name };
            db.IpReputations.Add(row);
        }
        row.Verdict = result.Verdict;
        row.Score = result.Score;
        row.Summary = Cut(result.Summary, 500);
        row.AttributesJson = result.Attributes is { Count: > 0 } ? Cut(JsonSerializer.Serialize(result.Attributes), 4000) : null;
        row.Error = Cut(result.Error, 500);
        row.CheckedAt = now;
        row.LastAttemptAt = now;
        row.LastAttemptError = null;

        // Keep the AbuseIPDB score on IpInfo too (dashboard, CSV and PDF read it from there).
        if (provider.Name == AbuseIpDbProvider.ProviderName && result.Score is int score && System.Net.IPAddress.TryParse(ip, out _))
        {
            var info = await db.IpInfos.FirstOrDefaultAsync(i => i.Ip == ip, ct);
            if (info is null)
                db.IpInfos.Add(new IpInfo { Ip = ip, AbuseScore = score });
            else
                info.AbuseScore = score;
        }
        return row;
    }

    /// <summary>SQL Server 2601 / 2627: duplicate key in a unique index / primary key.</summary>
    internal static bool IsUniqueViolation(DbUpdateException ex) =>
        ex.InnerException is Microsoft.Data.SqlClient.SqlException { Number: 2601 or 2627 };

    /// <summary>
    /// Background enrichment: each configured provider looks up the IPs that have no fresh answer yet,
    /// at most MaxPerRun per provider so free quotas are not burned on one big file.
    /// </summary>
    public async Task<int> EnrichAsync(IEnumerable<string> ips, CancellationToken ct)
    {
        var candidates = ips.Where(IpEnrichmentService.IsPublic).Distinct().ToList();
        if (candidates.Count == 0)
            return 0;

        var freshAfter = DateTime.UtcNow.AddDays(-Math.Max(0, _o.CacheDays));
        var lookups = 0;

        foreach (var provider in Providers.Where(p => p.IsConfigured))
        {
            var fresh = await db.IpReputations.AsNoTracking()
                .Where(r => r.Provider == provider.Name && candidates.Contains(r.Ip)
                            && r.CheckedAt > freshAfter && r.Verdict != ThreatVerdict.Error && r.Verdict != ThreatVerdict.Skipped)
                .Select(r => r.Ip)
                .ToListAsync(ct);
            var todo = candidates.Except(fresh).Take(Math.Max(0, provider.MaxPerRun)).ToList();

            foreach (var ip in todo)
            {
                await RefreshAsync(ip, provider, waitForSlot: true, ct);
                lookups++;
            }

            if (todo.Count > 0)
                logger.LogInformation("{Provider}: looked up {Count} IP(s), {Skipped} left for a later run",
                    provider.Name, todo.Count, candidates.Count - fresh.Count - todo.Count);
        }
        return lookups;
    }

    /// <summary>
    /// Alerts from IPs that GreyNoise classifies as benign (or RIOT business services) are lowered one severity level.
    /// The original severity is kept so the effect can be measured and undone.
    /// </summary>
    public async Task<int> ApplyGreyNoiseRuleAsync(int logFileId, CancellationToken ct)
    {
        if (!_o.GreyNoiseDowngradeBenign)
            return 0;

        var benign = await db.IpReputations.AsNoTracking()
            .Where(r => r.Provider == GreyNoiseProvider.ProviderName && r.Verdict == ThreatVerdict.Benign)
            .Select(r => new { r.Ip, r.Summary })
            .ToDictionaryAsync(r => r.Ip, r => r.Summary, ct);
        if (benign.Count == 0)
            return 0;

        var ips = benign.Keys.ToList();
        var alerts = await db.Alerts
            .Where(a => a.LogFileId == logFileId && a.OriginalSeverity == null && ips.Contains(a.SourceIp)
                        && a.Severity != Severity.Low)
            .ToListAsync(ct);

        foreach (var a in alerts)
        {
            a.OriginalSeverity = a.Severity;
            a.Severity = a.Severity - 1;
            a.SeverityNote = Cut($"Lowered from {a.OriginalSeverity}: GreyNoise - {benign[a.SourceIp]}", 300);
        }
        await db.SaveChangesAsync(ct);
        if (alerts.Count > 0)
            logger.LogInformation("GreyNoise rule lowered the severity of {Count} alert(s) in log file {Id}", alerts.Count, logFileId);
        return alerts.Count;
    }

    /// <summary>Full threat-intel step for one log file: lookups for alert sources, then the GreyNoise rule.</summary>
    public async Task<ThreatIntelRunSummary> RunForLogFileAsync(int logFileId, CancellationToken ct)
    {
        var ips = await db.Alerts.AsNoTracking()
            .Where(a => a.LogFileId == logFileId)
            .Select(a => a.SourceIp)
            .Distinct()
            .ToListAsync(ct);
        // Without AutoLookup nothing is sent; the GreyNoise rule still uses answers that analysts looked up by hand.
        var lookups = _o.AutoLookup ? await EnrichAsync(ips, ct) : 0;
        var downgraded = await ApplyGreyNoiseRuleAsync(logFileId, ct);
        return new ThreatIntelRunSummary(lookups, downgraded);
    }

    private static string? Cut(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];
}
