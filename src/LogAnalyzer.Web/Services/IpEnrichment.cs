using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using MaxMind.GeoIP2;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Services;

public sealed record GeoResult(string? CountryCode, string? CountryName, string? City, double? Latitude, double? Longitude);

/// <summary>
/// Offline IP geolocation with the MaxMind GeoLite2-City database.
/// No IP addresses leave the machine. If the .mmdb file is missing, lookups are simply disabled.
/// </summary>
public sealed class GeoIpLookup : IDisposable
{
    private readonly DatabaseReader? _reader;

    public GeoIpLookup(IConfiguration config, IWebHostEnvironment env, ILogger<GeoIpLookup> logger)
    {
        var path = config["Enrichment:GeoLiteCityDb"] ?? Path.Combine("App_Data", "GeoLite2-City.mmdb");
        if (!Path.IsPathRooted(path))
            path = Path.Combine(env.ContentRootPath, path);

        // Fallback: any city-level .mmdb in App_Data (MaxMind GeoLite2-City or DB-IP "dbip-city-lite").
        if (!File.Exists(path))
        {
            var appData = Path.Combine(env.ContentRootPath, "App_Data");
            path = Directory.Exists(appData)
                ? Directory.GetFiles(appData, "*.mmdb")
                    .Where(f => Path.GetFileName(f).Contains("city", StringComparison.OrdinalIgnoreCase))
                    .OrderByDescending(f => File.GetLastWriteTimeUtc(f))
                    .FirstOrDefault() ?? path
                : path;
        }

        if (!File.Exists(path))
        {
            logger.LogInformation("No GeoIP city database found in App_Data; country lookup is disabled");
            return;
        }

        try
        {
            _reader = new DatabaseReader(path);
            SourceName = Path.GetFileName(path).StartsWith("dbip", StringComparison.OrdinalIgnoreCase)
                ? "DB-IP" : "MaxMind GeoLite2";
            logger.LogInformation("GeoIP database loaded from {Path} ({Source})", path, SourceName);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not open GeoLite2 database at {Path}", path);
        }
    }

    public bool IsAvailable => _reader is not null;

    /// <summary>"DB-IP" or "MaxMind GeoLite2" — used for the attribution the licences require.</summary>
    public string? SourceName { get; private set; }

    public GeoResult? Lookup(string ip)
    {
        if (_reader is null)
            return null;
        try
        {
            if (_reader.TryCity(ip, out var r) && r is not null)
                return new GeoResult(r.Country.IsoCode, r.Country.Name, r.City.Name, r.Location.Latitude, r.Location.Longitude);
        }
        catch (Exception)
        {
            // Invalid or unknown address: treat as "no data"
        }
        return null;
    }

    public void Dispose() => _reader?.Dispose();
}

/// <summary>
/// Optional reputation lookup at AbuseIPDB (free tier: 1,000 checks/day).
/// Only used when an API key is configured (user secret "Enrichment:AbuseIpDbApiKey").
/// </summary>
public sealed class AbuseIpDbClient(HttpClient http, IConfiguration config, ILogger<AbuseIpDbClient> logger)
{
    private readonly string? _apiKey = config["Enrichment:AbuseIpDbApiKey"];

    public bool IsConfigured => !string.IsNullOrWhiteSpace(_apiKey);

    public async Task<int?> GetScoreAsync(string ip, CancellationToken ct)
    {
        if (!IsConfigured)
            return null;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get,
                $"https://api.abuseipdb.com/api/v2/check?ipAddress={Uri.EscapeDataString(ip)}&maxAgeInDays=90");
            request.Headers.Add("Key", _apiKey);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var response = await http.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("AbuseIPDB returned {Status} for {Ip}", (int)response.StatusCode, ip);
                return null;
            }

            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            return doc.RootElement.GetProperty("data").GetProperty("abuseConfidenceScore").GetInt32();
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException
                                       or KeyNotFoundException or InvalidOperationException)
        {
            logger.LogWarning(ex, "AbuseIPDB lookup failed for {Ip}", ip);
            return null;
        }
    }
}

/// <summary>Fills the IpInfos cache (country, city, coordinates, abuse score) for attacker IPs.</summary>
public sealed class IpEnrichmentService(
    AppDbContext db,
    GeoIpLookup geo,
    AbuseIpDbClient abuse,
    ILogger<IpEnrichmentService> logger)
{
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromDays(7);

    /// <summary>Enriches the source IPs of all alerts of one log file.</summary>
    public async Task EnrichAlertSourcesAsync(int logFileId, CancellationToken ct)
    {
        var ips = await db.Alerts.AsNoTracking()
            .Where(a => a.LogFileId == logFileId)
            .Select(a => a.SourceIp)
            .Distinct()
            .ToListAsync(ct);
        await EnrichAsync(ips, ct);
    }

    public async Task EnrichAsync(IEnumerable<string> ips, CancellationToken ct)
    {
        var candidates = ips.Where(ip => IPAddress.TryParse(ip, out _)).Distinct().ToList();
        if (candidates.Count == 0)
            return;

        var cached = await db.IpInfos.Where(i => candidates.Contains(i.Ip)).ToDictionaryAsync(i => i.Ip, ct);
        var freshAfter = DateTime.UtcNow - CacheLifetime;
        var updated = 0;

        foreach (var ip in candidates)
        {
            cached.TryGetValue(ip, out var info);

            // Skip fresh entries unless a data source became available since the last check.
            var missingGeo = info?.CountryCode is null && geo.IsAvailable;
            var missingAbuse = info?.AbuseScore is null && abuse.IsConfigured && IsPublic(ip);
            if (info is not null && info.LastChecked > freshAfter && !missingGeo && !missingAbuse)
                continue;

            if (info is null)
            {
                info = new IpInfo { Ip = ip };
                db.IpInfos.Add(info);
            }

            if (geo.Lookup(ip) is { } g)
            {
                info.CountryCode = g.CountryCode;
                info.CountryName = g.CountryName;
                info.City = g.City;
                info.Latitude = g.Latitude;
                info.Longitude = g.Longitude;
            }

            if (abuse.IsConfigured && IsPublic(ip))
                info.AbuseScore = await abuse.GetScoreAsync(ip, ct) ?? info.AbuseScore;

            info.LastChecked = DateTime.UtcNow;
            updated++;
        }

        await db.SaveChangesAsync(ct);
        logger.LogInformation("IP enrichment: {Updated} of {Total} addresses updated (GeoIP {Geo}, AbuseIPDB {Abuse})",
            updated, candidates.Count, geo.IsAvailable ? "on" : "off", abuse.IsConfigured ? "on" : "off");
    }

    /// <summary>Private, loopback and link-local addresses are never sent to external services.</summary>
    public static bool IsPublic(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address))
            return false;
        if (IPAddress.IsLoopback(address))
            return false;

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return !(b[0] == 10
                     || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                     || (b[0] == 192 && b[1] == 168)
                     || (b[0] == 169 && b[1] == 254)
                     || b[0] == 0
                     || b[0] >= 224);
        }

        return !(address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast
                 || (address.GetAddressBytes()[0] & 0xFE) == 0xFC); // fc00::/7 unique local
    }
}
