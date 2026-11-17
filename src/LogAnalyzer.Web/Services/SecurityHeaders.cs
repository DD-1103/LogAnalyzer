namespace LogAnalyzer.Web.Services;

/// <summary>
/// Adds browser security headers to every response. The Content-Security-Policy allows scripts, styles and fonts
/// only from this site (Bootstrap, Bootstrap Icons, Chart.js and Leaflet are self-hosted in wwwroot/lib):
/// no inline JavaScript, no eval, no plugins, no framing. Inline style attributes stay allowed (Bootstrap/Leaflet
/// use them); they cannot execute code. Only the OpenStreetMap map tiles come from another host.
/// Pages for signed-in users are marked no-store, so alerts and evidence do not stay in the browser cache.
/// </summary>
public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    public const string ContentSecurityPolicy =
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "font-src 'self'; " +
        "img-src 'self' data: https://tile.openstreetmap.org https://*.tile.openstreetmap.org; " +
        "connect-src 'self'; " +
        "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

    public Task InvokeAsync(HttpContext context)
    {
        context.Response.OnStarting(() =>
        {
            var h = context.Response.Headers;
            h["Content-Security-Policy"] = ContentSecurityPolicy;
            h["X-Content-Type-Options"] = "nosniff";
            h["X-Frame-Options"] = "DENY";
            h["Referrer-Policy"] = "strict-origin-when-cross-origin";
            h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";
            h["Cross-Origin-Opener-Policy"] = "same-origin";
            if (context.User.Identity?.IsAuthenticated == true)
            {
                h.CacheControl = "no-store, max-age=0";
                h.Pragma = "no-cache";
            }
            return Task.CompletedTask;
        });
        return next(context);
    }
}
