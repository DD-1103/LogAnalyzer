using System.Net;
using System.Net.Sockets;
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
/// Fills the IpInfos cache with offline GeoIP data (country, city, coordinates) for attacker IPs.
/// Reputation lookups (AbuseIPDB, GreyNoise, VirusTotal) are done by <see cref="ThreatIntelService"/>.
/// </summary>
public sealed class IpEnrichmentService(
    AppDbContext db,
    GeoIpLookup geo,
    ILogger<IpEnrichmentService> logger)
{
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromDays(7);

    /// <summary>Geolocates the source IPs of all alerts of one log file.</summary>
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
        var list = ips.ToList();
        try
        {
            await EnrichOnceAsync(list, ct);
        }
        catch (DbUpdateException ex) when (ThreatIntelService.IsUniqueViolation(ex))
        {
            // Another request inserted one of the same IPs meanwhile: start again from the stored rows.
            db.ChangeTracker.Clear();
            await EnrichOnceAsync(list, ct);
        }
    }

    private async Task EnrichOnceAsync(IEnumerable<string> ips, CancellationToken ct)
    {
        if (!geo.IsAvailable)
            return;

        var candidates = ips.Where(ip => IPAddress.TryParse(ip, out _)).Distinct().ToList();
        if (candidates.Count == 0)
            return;

        var cached = await db.IpInfos.Where(i => candidates.Contains(i.Ip)).ToDictionaryAsync(i => i.Ip, ct);
        var freshAfter = DateTime.UtcNow - CacheLifetime;
        var updated = 0;

        foreach (var ip in candidates)
        {
            cached.TryGetValue(ip, out var info);
            if (info is not null && info.LastChecked > freshAfter && info.CountryCode is not null)
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

            info.LastChecked = DateTime.UtcNow;
            updated++;
        }

        await db.SaveChangesAsync(ct);
        logger.LogInformation("GeoIP enrichment: {Updated} of {Total} addresses updated", updated, candidates.Count);
    }

    /// <summary>Only public unicast addresses are ever sent to external services (see <see cref="IpAddressPolicy"/>).</summary>
    public static bool IsPublic(string ip) => IpAddressPolicy.IsPublic(ip);
}
