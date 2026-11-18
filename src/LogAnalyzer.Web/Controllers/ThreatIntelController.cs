using System.Net;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Controllers;

/// <summary>
/// Threat-intelligence providers (AbuseIPDB, GreyNoise, VirusTotal):
///   GET  /ThreatIntel                      search bar (IP, domain, hash) + recent lookups
///   GET  /ThreatIntel/Providers            configuration status of every provider, GreyNoise effect
///   GET  /ThreatIntel/Provider/{slug}      one provider: setup, quota, cached answers, test
///   GET  /ThreatIntel/Lookup?q=            everything known about one IP, domain or file hash (cached)
///   POST /ThreatIntel/Search               "Look up": all configured providers that support the type
///   POST /ThreatIntel/Refresh              forced live lookup (one or all providers)
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

    /// <summary>The threat-intel start page: one search bar, the providers that will answer, recent lookups.</summary>
    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var recentKeys = await db.IpReputations.AsNoTracking()
            .Where(r => r.Verdict != ThreatVerdict.Skipped)
            .GroupBy(r => r.Ip)
            .Select(g => new { Ip = g.Key, Last = g.Max(x => x.CheckedAt) })
            .OrderByDescending(x => x.Last)
            .Take(8)
            .ToListAsync(ct);
        var ips = recentKeys.Select(k => k.Ip).ToList();
        var rows = await db.IpReputations.AsNoTracking().Where(r => ips.Contains(r.Ip)).ToListAsync(ct);

        return View(new ThreatIntelSearchViewModel
        {
            Providers = threatIntel.Providers,
            Recent = recentKeys.Select(k =>
            {
                var answers = rows.Where(r => r.Ip == k.Ip).ToList();
                return new RecentLookup(k.Ip, answers.First().Kind, ThreatConsensus.Compute(answers), k.Last);
            }).ToList()
        });
    }

    /// <summary>Provider set-up and statistics (configuration, cached answers, GreyNoise effect).</summary>
    [HttpGet]
    public async Task<IActionResult> Providers(CancellationToken ct)
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
        return View("Providers", model);
    }

    [HttpGet]
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

    /// <summary>
    /// Everything known about one indicator (IP, domain or file hash): cached provider answers and, for IPs,
    /// location, alerts and requests. Reading this page never contacts a provider; "Look up" (POST Search) does.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> Lookup(string? q, string? ip, CancellationToken ct)
    {
        var query = string.IsNullOrWhiteSpace(q) ? ip : q;
        var model = new ThreatIntelLookupViewModel { Providers = threatIntel.Providers, Query = query?.Trim() };
        if (string.IsNullOrWhiteSpace(query))
            return View(model);
        if (!IndicatorParser.TryParse(query, out var indicator, out var error))
        {
            model.Error = error;
            return View(model);
        }

        model.Indicator = indicator;
        model.Ip = indicator.Value;
        model.IsPublic = IndicatorParser.MaySend(indicator, threatIntel.InternalDomains, out var blocked);
        model.BlockedReason = model.IsPublic ? null : blocked;
        model.Results = (await threatIntel.GetCachedAsync(indicator.Value, ct)).ToDictionary(r => r.Provider);
        // The LogAnalyzer verdict counts only providers that are configured and support this type of indicator.
        var usable = threatIntel.Providers.Where(p => p.IsConfigured && p.Supports(indicator.Type)).Select(p => p.Name).ToHashSet();
        model.Consensus = ThreatConsensus.Compute(model.Results.Values.Where(r => usable.Contains(r.Provider)));
        if (indicator.Type == IndicatorType.Ip)
        {
            model.IpInfo = await db.IpInfos.AsNoTracking().FirstOrDefaultAsync(i => i.Ip == indicator.Value, ct);
            model.AlertCount = await db.Alerts.CountAsync(a => a.SourceIp == indicator.Value, ct);
            model.EventCount = await db.LogEvents.CountAsync(e => e.ClientIp == indicator.Value, ct);
        }
        return View(model);
    }

    /// <summary>
    /// "Look up": checks the indicator at every configured provider that supports its type (cached answers younger
    /// than CacheDays are reused), then shows the result page. Unconfigured providers are never called.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    [EnableRateLimiting("ti-lookup")]
    public async Task<IActionResult> Search(string? q, CancellationToken ct)
    {
        if (!IndicatorParser.TryParse(q, out var indicator, out var error))
        {
            TempData["Error"] = error;
            return RedirectToAction(nameof(Lookup), new { q });
        }

        var results = await threatIntel.LookupEverywhereAsync(indicator, UiMaxWait, ct);
        if (results.Count > 0)
        {
            var summary = string.Join("; ", results.Select(r => $"{r.Provider}: {r.Verdict}"));
            await audit.WriteAsync("ThreatIntel.Lookup", $"{indicator.Label} {indicator.Value}", summary, ct);
            logger.LogInformation("User {User} looked up {Type} {Indicator}: {Result}",
                User.Identity?.Name, indicator.Type, indicator.Value, summary);
        }
        return RedirectToAction(nameof(Lookup), new { q = indicator.Value });
    }

    /// <summary>A UI lookup waits at most this long for a rate-limited provider (VirusTotal: 4 requests/minute).</summary>
    private static readonly TimeSpan UiMaxWait = TimeSpan.FromSeconds(16);

    /// <summary>Live lookup. provider = slug, or empty for all configured providers.</summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    [EnableRateLimiting("ti-lookup")]
    public async Task<IActionResult> Refresh(string ip, string? provider, string? returnUrl, CancellationToken ct)
    {
        // "ip" carries any indicator (IP, domain or hash) for compatibility with existing forms.
        if (!IndicatorParser.TryParse(ip, out var indicator, out var error))
        {
            TempData["Error"] = error;
            return RedirectToAction(nameof(Lookup));
        }
        var address = indicator.Value;

        var targets = string.IsNullOrEmpty(provider)
            ? threatIntel.Providers.Where(p => p.IsConfigured && p.Supports(indicator.Type)).ToList()
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
                var r = await threatIntel.RefreshAsync(indicator, p, waitForSlot: false, ct, UiMaxWait);
                messages.Add(r.LastAttemptError is not null
                    ? $"{p.Name}: {r.Verdict} kept (refresh failed – {r.LastAttemptError})"
                    : $"{p.Name}: {r.Verdict}{(r.Error is null ? "" : " – " + r.Error)}");
            }
            await audit.WriteAsync("ThreatIntel.Lookup", address, string.Join("; ", messages), ct);
            logger.LogInformation("User {User} refreshed threat intel for {Ip}: {Result}",
                User.Identity?.Name, address, string.Join("; ", messages));
            TempData["Success"] = "Lookup finished. " + string.Join(" · ", messages);
        }

        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            return LocalRedirect(returnUrl);
        return RedirectToAction(nameof(Lookup), new { q = address });
    }

    /// <summary>Checks the API key of one provider with a harmless lookup of 8.8.8.8.</summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = Roles.Admin)]
    [EnableRateLimiting("ti-lookup")]
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
        if (!IPAddress.TryParse(value.Trim(), out _))
            return false;
        // Same canonical form the parser stores (finding 24), so counts and cache rows match.
        address = IpAddressPolicy.Canonical(value.Trim());
        return true;
    }
}
