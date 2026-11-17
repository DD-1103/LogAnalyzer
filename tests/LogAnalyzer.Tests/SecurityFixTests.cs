using System.Net;
using System.Security.Claims;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.ViewModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;

namespace LogAnalyzer.Tests;

/// <summary>Regression tests for the fixes of the 2026-11-17 security audit (docs/security-audit).</summary>
public class SecurityFixTests
{
    // ---- 15: empty rule name must give a validation message, not a NullReferenceException ----

    [Fact]
    public void RuleForm_Normalize_WithNullName_DoesNotThrow()
    {
        var model = new RuleFormModel { Name = null!, Kind = RuleKind.Signature, Pattern = "x" };
        model.Normalize();
        Assert.Equal(string.Empty, model.Name);
    }

    // ---- 21: rate-limit partition key ----

    [Theory]
    [InlineData("203.0.113.7", "203.0.113.7")]
    [InlineData("::ffff:203.0.113.7", "203.0.113.7")]
    [InlineData("2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64")]
    [InlineData("2001:db8:1:2::1", "2001:db8:1:2::/64")]
    public void RateLimitKey_GroupsIpv6By64AndUnmapsIpv4(string ip, string expected) =>
        Assert.Equal(expected, ClientNetwork.RateLimitKey(IPAddress.Parse(ip)));

    [Fact]
    public void RateLimitKey_NullAddress() => Assert.Equal("unknown", ClientNetwork.RateLimitKey(null));

    // ---- 12: users with a temporary password are sent to "Change password" ----

    private static AuthorizationFilterContext FilterContext(string controller, string action, bool mustChange,
        bool authenticated = true, string? accept = null)
    {
        var claims = new List<Claim> { new(ClaimTypes.Name, "user@example.test") };
        if (mustChange)
            claims.Add(new Claim(AppUserClaimsPrincipalFactory.MustChangePasswordClaim, "true"));
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(authenticated ? new ClaimsIdentity(claims, "test") : new ClaimsIdentity())
        };
        if (accept is not null)
            http.Request.Headers.Accept = accept;
        var descriptor = new ControllerActionDescriptor { ControllerName = controller, ActionName = action };
        return new AuthorizationFilterContext(new ActionContext(http, new RouteData(), descriptor), []);
    }

    [Fact]
    public void PasswordFilter_RedirectsFlaggedUser()
    {
        var ctx = FilterContext("Alerts", "Index", mustChange: true);
        new RequirePasswordChangeFilter().OnAuthorization(ctx);
        var redirect = Assert.IsType<RedirectToActionResult>(ctx.Result);
        Assert.Equal("Account", redirect.ControllerName);
        Assert.Equal("ChangePassword", redirect.ActionName);
    }

    [Theory]
    [InlineData("Account", "ChangePassword")]
    [InlineData("Account", "Logout")]
    [InlineData("Home", "Error")]
    public void PasswordFilter_LeavesAccountPagesOpen(string controller, string action)
    {
        var ctx = FilterContext(controller, action, mustChange: true);
        new RequirePasswordChangeFilter().OnAuthorization(ctx);
        Assert.Null(ctx.Result);
    }

    [Fact]
    public void PasswordFilter_IgnoresNormalUsers()
    {
        var ctx = FilterContext("Alerts", "Index", mustChange: false);
        new RequirePasswordChangeFilter().OnAuthorization(ctx);
        Assert.Null(ctx.Result);
    }

    [Fact]
    public void PasswordFilter_JsonRequestsGet403()
    {
        var ctx = FilterContext("Home", "NavCounts", mustChange: true, accept: "application/json");
        new RequirePasswordChangeFilter().OnAuthorization(ctx);
        Assert.Equal(403, Assert.IsType<StatusCodeResult>(ctx.Result).StatusCode);
    }

    // ---- 26: CSP without third-party script hosts, no-store for signed-in pages ----

    private sealed class CapturingResponseFeature : HttpResponseFeature
    {
        private readonly List<(Func<object, Task> Callback, object State)> _starting = [];
        public override void OnStarting(Func<object, Task> callback, object state) => _starting.Add((callback, state));

        public async Task StartAsync()
        {
            foreach (var (callback, state) in _starting)
                await callback(state);
        }
    }

    private static async Task<IHeaderDictionary> RunHeadersAsync(bool authenticated)
    {
        var feature = new CapturingResponseFeature();
        var http = new DefaultHttpContext();
        http.Features.Set<IHttpResponseFeature>(feature);
        if (authenticated)
            http.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, "u")], "test"));
        await new SecurityHeadersMiddleware(_ => Task.CompletedTask).InvokeAsync(http);
        await feature.StartAsync();
        return http.Response.Headers;
    }

    [Fact]
    public async Task Headers_SignedInResponseIsNoStore()
    {
        var headers = await RunHeadersAsync(authenticated: true);
        Assert.Contains("no-store", headers.CacheControl.ToString());
    }

    [Fact]
    public async Task Headers_AnonymousResponseKeepsCaching()
    {
        var headers = await RunHeadersAsync(authenticated: false);
        Assert.True(string.IsNullOrEmpty(headers.CacheControl.ToString()));
    }

    [Fact]
    public void Csp_AllowsScriptsOnlyFromSelf()
    {
        var csp = SecurityHeadersMiddleware.ContentSecurityPolicy;
        Assert.Contains("script-src 'self';", csp);
        Assert.DoesNotContain("jsdelivr", csp);
        Assert.DoesNotContain("unsafe-eval", csp);
    }

    [Fact]
    public void Views_ReferenceNoExternalScriptsOrStyles()
    {
        var views = Path.Combine(RepoRoot(), "src", "LogAnalyzer.Web", "Views");
        foreach (var file in Directory.EnumerateFiles(views, "*.cshtml", SearchOption.AllDirectories))
        {
            var text = File.ReadAllText(file);
            Assert.False(text.Contains("<script src=\"http", StringComparison.OrdinalIgnoreCase), file);
            Assert.False(text.Contains("rel=\"stylesheet\" href=\"http", StringComparison.OrdinalIgnoreCase), file);
        }
    }

    internal static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "LogAnalyzer.slnx")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }
}
