using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Mvc.ViewFeatures.Infrastructure;
using Microsoft.Extensions.Options;

namespace LogAnalyzer.Web.Services;

/// <summary>
/// Several accounts signed in at the same time in one browser (like Gmail's /u/1/). A browser keeps one cookie per
/// name, so one sign-in cookie would allow only one user per browser. Every tab can instead work in a session slot:
/// <c>/s/1/...</c> to <c>/s/9/...</c>; no prefix is slot 0 (the normal URLs). <see cref="SessionSlotMiddleware"/>
/// moves the prefix into Request.PathBase, so every link, form, redirect and static file URL the app generates keeps
/// it automatically, and <see cref="SessionSlotCookieManager"/> gives each slot its own sign-in cookie
/// (<c>.AspNetCore.Identity.Application.s2</c>). Slot 0 keeps the original cookie name (existing sign-ins survive).
/// </summary>
public static class SessionSlots
{
    public const int MaxSlot = 9;

    private const string Prefix = "/s/";
    private static readonly object SlotKey = new();
    private static readonly object RootKey = new();

    /// <summary>
    /// "/s/{1-9}" or "/s/{1-9}/..." (lower-case "s", one digit, nothing else) → the slot and the rest of the path.
    /// Everything else (/s/0, /s/10, /s/x, /S/2, /s2/x) is not a slot path and is left alone (normal 404).
    /// </summary>
    public static bool TryParse(PathString path, out int slot, out PathString remainder)
    {
        slot = 0;
        remainder = path;
        var value = path.Value;
        if (value is null || value.Length < 4 || !value.StartsWith(Prefix, StringComparison.Ordinal))
            return false;
        var digit = value[3];
        if (digit is < '1' or > '9' || (value.Length > 4 && value[4] != '/'))
            return false;

        slot = digit - '0';
        remainder = value.Length <= 5 ? new PathString("/") : new PathString(value[4..]);
        return true;
    }

    /// <summary>Called by the middleware: remembers the slot and the application's own path base.</summary>
    public static void Set(HttpContext context, int slot, PathString rootPathBase)
    {
        context.Items[SlotKey] = slot;
        context.Items[RootKey] = rootPathBase;
    }

    /// <summary>Session slot of this request (0 = the default session without a URL prefix).</summary>
    public static int Current(HttpContext? context) =>
        context?.Items.TryGetValue(SlotKey, out var value) == true && value is int slot ? slot : 0;

    /// <summary>Path base of the application without the slot prefix ("" when hosted at the site root).</summary>
    public static PathString RootPathBase(HttpContext context) =>
        context.Items.TryGetValue(RootKey, out var value) && value is PathString root ? root : context.Request.PathBase;

    /// <summary>Path base of another slot, e.g. for "Sign in another account" (slot 3 → "/s/3").</summary>
    public static PathString PathBaseFor(HttpContext context, int slot)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(slot);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(slot, MaxSlot);
        var root = RootPathBase(context);
        return slot == 0 ? root : root.Add(new PathString(Prefix + slot));
    }

    /// <summary>Cookie name of a slot: slot 0 keeps the configured name, slot n gets ".s{n}" appended.</summary>
    public static string CookieName(string baseName, int slot) => slot == 0 ? baseName : $"{baseName}.s{slot}";

    /// <summary>Slots (0-9) that have a sign-in cookie in this request; all are sent because the cookie path is "/".</summary>
    public static IReadOnlyList<int> UsedSlots(IEnumerable<string> requestCookieNames, string baseName)
    {
        var names = requestCookieNames.ToHashSet(StringComparer.Ordinal);
        return Enumerable.Range(0, MaxSlot + 1).Where(s => names.Contains(CookieName(baseName, s))).ToList();
    }

    /// <summary>Lowest slot 1-9 without a sign-in cookie, or null when all nine are in use.</summary>
    public static int? FirstFreeSlot(IEnumerable<string> requestCookieNames, string baseName)
    {
        var used = UsedSlots(requestCookieNames, baseName);
        for (var slot = 1; slot <= MaxSlot; slot++)
            if (!used.Contains(slot))
                return slot;
        return null;
    }

    /// <summary>The URL of this request as the browser sees it (path base + path [+ query]), for return URLs.</summary>
    public static string CurrentUrl(HttpRequest request, bool includeQuery = true) =>
        request.PathBase.Add(request.Path).ToUriComponent() + (includeQuery ? request.QueryString.ToUriComponent() : "");

    /// <summary>
    /// A return URL is followed only when it is local (like Url.IsLocalUrl: "/x", not "//host", "/\host" or absolute)
    /// and stays in the session slot of this request: a sign-in in slot 2 never lands on a page of slot 0 or 3,
    /// where a different user may be signed in. The check is made on the path as browser and server will read it:
    /// percent-encoding is decoded, and paths that are rewritten after the check ("..", "." or "\", also encoded) are
    /// refused. Only printable ASCII is accepted (a Location header cannot hold anything else).
    /// </summary>
    public static bool IsLocalToCurrentSlot(HttpRequest request, string? url)
    {
        if (!IsLocalPath(url) || url!.Any(c => c is < '!' or > '~'))
            return false;
        var path = Uri.UnescapeDataString(url!.Split('?', '#')[0]);
        if (!IsLocalPath(path) || path.Contains('\\') || path.Split('/').Any(s => s is "." or ".."))
            return false;
        var pathBase = request.PathBase.Value ?? "";
        if (pathBase.Length > 0)
        {
            // Case-sensitive like TryParse: "/S/2" is not slot 2.
            if (!path.StartsWith(pathBase, StringComparison.Ordinal))
                return false;
            if (path.Length > pathBase.Length && path[pathBase.Length] != '/')
                return false;
        }
        if (Current(request.HttpContext) != 0)
            return true;
        // In slot 0 the rest of the path must not be another slot's prefix.
        var rest = path.Length == pathBase.Length ? "/" : path[pathBase.Length..];
        return !TryParse(new PathString(rest), out _, out _);
    }

    /// <summary>
    /// Notification links are stored app-relative ("/Alerts/Details/5"); on screen they get the path base of the
    /// current slot so a click stays in the same session. Anything that is not a plain local path → null (no link).
    /// </summary>
    public static string? AppLink(PathString pathBase, string? link) =>
        IsLocalPath(link) ? pathBase.ToUriComponent() + link : null;

    /// <summary>"/..." but not "//...", "/\..." or anything with a scheme or control characters.</summary>
    public static bool IsLocalPath(string? url) =>
        !string.IsNullOrEmpty(url) && url[0] == '/'
        && (url.Length == 1 || (url[1] != '/' && url[1] != '\\'))
        && !url.Any(char.IsControl);
}

/// <summary>
/// First middleware of the pipeline: "/s/2/Alerts" → PathBase "/s/2", Path "/Alerts", slot 2 for the request.
/// </summary>
public sealed class SessionSlotMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var request = context.Request;
        if (!SessionSlots.TryParse(request.Path, out var slot, out var remainder))
        {
            SessionSlots.Set(context, 0, request.PathBase);
            await next(context);
            return;
        }

        var originalPathBase = request.PathBase;
        var originalPath = request.Path;
        SessionSlots.Set(context, slot, originalPathBase);
        request.PathBase = originalPathBase.Add(new PathString("/s/" + slot));
        request.Path = remainder;
        try
        {
            await next(context);
        }
        finally
        {
            request.PathBase = originalPathBase;
            request.Path = originalPath;
        }
    }
}

/// <summary>
/// Cookie manager of the Identity cookies: each session slot reads, writes and deletes its own cookie
/// (name + ".s{n}"; chunks of large cookies follow as name.s{n}C1, C2, ...). Sign-in, sign-out, sliding renewal and
/// the security-stamp check all go through the cookie handler and therefore through this manager.
/// </summary>
public sealed class SessionSlotCookieManager : ICookieManager
{
    private readonly ChunkingCookieManager inner = new();

    public string? GetRequestCookie(HttpContext context, string key) =>
        inner.GetRequestCookie(context, SessionSlots.CookieName(key, SessionSlots.Current(context)));

    public void AppendResponseCookie(HttpContext context, string key, string? value, CookieOptions options) =>
        inner.AppendResponseCookie(context, SessionSlots.CookieName(key, SessionSlots.Current(context)), value, options);

    public void DeleteCookie(HttpContext context, string key, CookieOptions options) =>
        inner.DeleteCookie(context, SessionSlots.CookieName(key, SessionSlots.Current(context)), options);
}

/// <summary>
/// TempData (the green/red messages after an action) in a cookie per session slot. The default provider uses one
/// cookie name with the path base as cookie path, so the slot 0 cookie (path "/") would also be sent to /s/2 and two
/// cookies with the same name would compete. Here every slot has its own name and the path is always "/".
/// </summary>
public sealed class SessionSlotTempDataProvider : ITempDataProvider
{
    private readonly CookieTempDataProvider[] bySlot;

    public SessionSlotTempDataProvider(IDataProtectionProvider dataProtection, ILoggerFactory loggerFactory,
        IOptions<CookieTempDataProviderOptions> options, TempDataSerializer serializer)
    {
        bySlot = new CookieTempDataProvider[SessionSlots.MaxSlot + 1];
        for (var slot = 0; slot <= SessionSlots.MaxSlot; slot++)
        {
            var source = options.Value.Cookie;
            var copy = new CookieTempDataProviderOptions();
            copy.Cookie.Name = SessionSlots.CookieName(source.Name ?? CookieTempDataProvider.CookieName, slot);
            copy.Cookie.Path = "/";
            copy.Cookie.Domain = source.Domain;
            copy.Cookie.HttpOnly = source.HttpOnly;
            copy.Cookie.SameSite = source.SameSite;
            copy.Cookie.SecurePolicy = source.SecurePolicy;
            copy.Cookie.IsEssential = source.IsEssential;
            copy.Cookie.MaxAge = source.MaxAge;
            bySlot[slot] = new CookieTempDataProvider(dataProtection, loggerFactory, Options.Create(copy), serializer);
        }
    }

    public IDictionary<string, object> LoadTempData(HttpContext context) =>
        bySlot[SessionSlots.Current(context)].LoadTempData(context);

    public void SaveTempData(HttpContext context, IDictionary<string, object> values) =>
        bySlot[SessionSlots.Current(context)].SaveTempData(context, values);
}
