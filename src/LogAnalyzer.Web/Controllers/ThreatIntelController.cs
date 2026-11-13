using System.Net;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Controllers;

/// <summary>
/// Threat-intelligence providers (AbuseIPDB, GreyNoise, VirusTotal):
///   GET  /ThreatIntel                      overview, configuration status, GreyNoise effect
///   GET  /ThreatIntel/Provider/{slug}      one provider: setup, quota, cached answers, test
///   GET  /ThreatIntel/Lookup?ip=           everything known about one IP
///   POST /ThreatIntel/Refresh              live lookup of one IP (one or all providers)
///   POST /ThreatIntel/Test/{slug}          Admin: checks that the API key works (8.8.8.8)
///   GET  /ThreatIntel/Api/{slug}/{ip}      cached answer as JSON
/// </summary>
public class ThreatIntelController(
    ThreatIntelService threatIntel,
    AppDbContext db,
    IAuditLog audit,
    ILogger<ThreatIntelController> logger) : Controller
{
    // Google Public DNS: every provider knows it, so it is a safe address to test an API key with.
    private const string TestIp = "8.8.8.8";
    private const int PageSize = 50;

    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var verdicts = await db.IpReputations.AsNoTracking()
            .GroupBy(r => new { r.Provider, r.Verdict })
            .Select(g => new { g.Key.Provider, g.Key.Verdict, Count = g.Count() })
            .ToListAsync(ct);

        var downgraded = await db.Alerts.AsNoTracking()
            .Where(a => a.OriginalSeverity != null)
            .GroupBy(a => new { a.OriginalSeverity, a.Severity })
            .Select(g => new { g.Key.OriginalSeverity, g.Key.Severity, Count = g.Count() })
            .ToListAsync(ct);

        var model = new ThreatIntelIndexViewModel
        {
            Providers = threatIntel.Providers.Select(p => new ProviderStatus(p,
                verdicts.Where(v => v.Provider == p.Name).ToDictionary(v => v.Verdict, v => v.Count))).ToList(),
            TotalAlerts = await db.Alerts.CountAsync(ct),
            Downgrades = downgraded
                .Select(d => new SeverityChange(d.OriginalSeverity!.Value, d.Severity, d.Count))
                .OrderByDescending(d => d.From)
                .ToList(),
            Recent = await db.IpReputations.AsNoTracking()
                .OrderByDescending(r => r.CheckedAt)
                .Take(15)
                .ToListAsync(ct)
        };
        return View(model);
    }

    public async Task<IActionResult> Provider(string id, int page = 1, CancellationToken ct = default)
    {
        var provider = threatIntel.Find(id);
        if (provider is null)
            return NotFound();

        var query = db.IpReputations.AsNoTracking().Where(r => r.Provider == provider.Name);
        var count = await query.CountAsync(ct);
        var totalPages = Math.Max(1, (int)Math.Ceiling(count / (double)PageSize));
        page = Math.Clamp(page, 1, totalPages);

        return View(new ThreatIntelProviderViewModel
        {
            Provider = provider,
            Results = await query
                .OrderByDescending(r => r.Verdict == ThreatVerdict.Malicious ? 3 : r.Verdict == ThreatVerdict.Suspicious ? 2 : 0)
                .ThenByDescending(r => r.CheckedAt)
                .Skip((page - 1) * PageSize)
                .Take(PageSize)
                .ToListAsync(ct),
            Page = page,
            TotalPages = totalPages,
            TotalCount = count
        });
    }

    public async Task<IActionResult> Lookup(string? ip, CancellationToken ct)
    {
        var model = new ThreatIntelLookupViewModel { Providers = threatIntel.Providers };
        if (string.IsNullOrWhiteSpace(ip))
            return View(model);

        if (!TryNormalize(ip, out var address))
        {
            model.Error = "Enter a valid IPv4 or IPv6 address.";
            model.Ip = ip;
            return View(model);
        }

        model.Ip = address;
        model.IsPublic = IpEnrichmentService.IsPublic(address);
        model.Results = (await threatIntel.GetCachedAsync(address, ct)).ToDictionary(r => r.Provider);
        model.IpInfo = await db.IpInfos.AsNoTracking().FirstOrDefaultAsync(i => i.Ip == address, ct);
        model.AlertCount = await db.Alerts.CountAsync(a => a.SourceIp == address, ct);
        model.EventCount = await db.LogEvents.CountAsync(e => e.ClientIp == address, ct);
        return View(model);
    }

    /// <summary>Live lookup. provider = slug, or empty for all configured providers.</summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Refresh(string ip, string? provider, string? returnUrl, CancellationToken ct)
    {
        if (!TryNormalize(ip, out var address))
        {
            TempData["Error"] = "Invalid IP address.";
            return RedirectToAction(nameof(Lookup));
        }

        var targets = string.IsNullOrEmpty(provider)
            ? threatIntel.Providers.Where(p => p.IsConfigured).ToList()
            : threatIntel.Find(provider) is { } one ? [one] : [];

        if (targets.Count == 0)
        {
            TempData["Error"] = string.IsNullOrEmpty(provider)
                ? "No threat-intel provider is configured yet. Add an API key with dotnet user-secrets (see Threat intel page)."
                : "Unknown provider.";
        }
        else
        {
            var messages = new List<string>();
            foreach (var p in targets)
            {
                var r = await threatIntel.RefreshAsync(address, p, waitForSlot: false, ct);
                messages.Add($"{p.Name}: {r.Verdict}{(r.Error is null ? "" : " – " + r.Error)}");
            }
            await audit.WriteAsync("ThreatIntel.Lookup", address, string.Join("; ", messages), ct);
            logger.LogInformation("User {User} refreshed threat intel for {Ip}: {Result}",
                User.Identity?.Name, address, string.Join("; ", messages));
            TempData["Success"] = "Lookup finished. " + string.Join(" · ", messages);
        }

        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            return LocalRedirect(returnUrl);
        return RedirectToAction(nameof(Lookup), new { ip = address });
    }

    /// <summary>Checks the API key of one provider with a harmless lookup of 8.8.8.8.</summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Test(string id, CancellationToken ct)
    {
        var provider = threatIntel.Find(id);
        if (provider is null)
            return NotFound();

        if (!provider.IsConfigured)
        {
            TempData["Error"] = $"{provider.Name} has no API key yet. Run: dotnet user-secrets set \"{provider.ApiKeySetting}\" \"YOUR_KEY\"";
            return RedirectToAction(nameof(Provider), new { id = provider.Slug });
        }

        var r = await threatIntel.RefreshAsync(TestIp, provider, waitForSlot: false, ct);
        await audit.WriteAsync("ThreatIntel.Test", provider.Name, $"{r.Verdict} {r.Error}", ct);
        if (r.Verdict == ThreatVerdict.Error)
            TempData["Error"] = $"{provider.Name} test failed: {r.Error}";
        else
            TempData["Success"] = $"{provider.Name} works. {TestIp}: {r.Verdict} – {r.Summary}";
        return RedirectToAction(nameof(Provider), new { id = provider.Slug });
    }

    /// <summary>Cached answer of one provider for one IP, as JSON (no external call).</summary>
    [HttpGet("ThreatIntel/Api/{provider}/{ip}")]
    public async Task<IActionResult> Api(string provider, string ip, CancellationToken ct)
    {
        var p = threatIntel.Find(provider);
        if (p is null)
            return NotFound(new { error = "Unknown provider", providers = threatIntel.Providers.Select(x => x.Slug) });
        if (!TryNormalize(ip, out var address))
            return BadRequest(new { error = "Invalid IP address" });

        var row = await db.IpReputations.AsNoTracking()
            .FirstOrDefaultAsync(r => r.Ip == address && r.Provider == p.Name, ct);

        return Json(new
        {
            provider = p.Name,
            configured = p.IsConfigured,
            ip = address,
            cached = row is not null,
            verdict = row?.Verdict.ToString(),
            score = row?.Score,
            summary = row?.Summary,
            attributes = row?.GetAttributes(),
            error = row?.Error,
            checkedAt = row?.CheckedAt
        });
    }

    private static bool TryNormalize(string? value, out string address)
    {
        address = string.Empty;
        // Only accept dotted / colon notation (IPAddress.TryParse also accepts "1" as 0.0.0.1).
        if (string.IsNullOrWhiteSpace(value) || value.Length > 45 || !(value.Contains('.') || value.Contains(':')))
            return false;
        if (!IPAddress.TryParse(value.Trim(), out var parsed))
            return false;
        address = parsed.ToString();
        return true;
    }
}
