namespace LogAnalyzer.Web.Services;

/// <summary>
/// Adds browser security headers to every response. The Content-Security-Policy allows scripts only from this
/// site and the jsDelivr CDN (Bootstrap, Chart.js, Leaflet): no inline JavaScript, no eval, no plugins, no framing.
/// Inline style attributes stay allowed (Bootstrap/Leaflet use them); they cannot execute code.
/// </summary>
public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    public const string ContentSecurityPolicy =
        "default-src 'self'; " +
        "script-src 'self' https://cdn.jsdelivr.net; " +
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; " +
        "font-src 'self' https://cdn.jsdelivr.net; " +
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
            return Task.CompletedTask;
        });
        return next(context);
    }
}
