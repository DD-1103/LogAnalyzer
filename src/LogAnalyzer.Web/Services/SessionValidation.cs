using System.Security.Claims;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Core.Infrastructure;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Options;

namespace LogAnalyzer.Web.Services;

/// <summary>
/// The sign-in cookie is normally re-checked against the database only once a minute (security stamp validation).
/// For everything that changes data (POST) and for every admin-only page this filter checks the user right away:
/// account still enabled, cookie not revoked (security stamp unchanged: logout, password change, role change,
/// disable) and, for admin pages, still an administrator. A disabled or demoted admin can no longer act in that minute,
/// and a copied cookie stops working as soon as its owner logs out.
/// </summary>
public sealed class RevalidateSessionFilter(
    UserManager<AppUser> userManager,
    SignInManager<AppUser> signInManager,
    IOptions<IdentityOptions> identityOptions,
    ILogger<RevalidateSessionFilter> logger) : IAsyncAuthorizationFilter
{
    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var http = context.HttpContext;
        if (http.User.Identity?.IsAuthenticated != true)
            return;

        var adminOnly = RequiresAdmin(context.ActionDescriptor.EndpointMetadata);
        var readOnly = HttpMethods.IsGet(http.Request.Method) || HttpMethods.IsHead(http.Request.Method);
        if (readOnly && !adminOnly)
            return;

        var id = userManager.GetUserId(http.User);
        var stamp = http.User.FindFirstValue(identityOptions.Value.ClaimsIdentity.SecurityStampClaimType);
        var user = id is null ? null : await userManager.FindByIdAsync(id);
        var valid = user is not null && !user.IsDisabled && stamp == user.SecurityStamp
                    && (!adminOnly || await userManager.IsInRoleAsync(user, Roles.Admin));
        if (valid)
            return;

        logger.LogWarning("Revoked session of {User} rejected for {Method} {Path}",
            AuditLog.Clean(http.User.Identity?.Name), http.Request.Method, http.Request.Path);
        await signInManager.SignOutAsync();
        context.Result = http.Request.Headers.Accept.ToString().Contains("application/json", StringComparison.OrdinalIgnoreCase)
            ? new StatusCodeResult(StatusCodes.Status401Unauthorized)
            // Back to the same page (with its session prefix /s/n) after signing in again; a POST cannot be repeated
            // by a redirect, so it starts at the home page of the session instead.
            : new RedirectToActionResult("Login", "Account", new { returnUrl = readOnly ? SessionSlots.CurrentUrl(http.Request) : null });
    }

    public static bool RequiresAdmin(IEnumerable<object> metadata) =>
        metadata.OfType<IAuthorizeData>().Any(a =>
            a.Roles?.Split(',', StringSplitOptions.TrimEntries).Contains(Roles.Admin) == true);
}

/// <summary>
/// What a visitor without a (valid) sign-in gets. Background requests (bell, navigation badges) get 401 / 403 instead
/// of a redirect: fetch() would follow it, receive the sign-in page with status 200 and take that for success. Forms
/// are sent to the sign-in page without a return URL, because a POST-only address cannot be opened after signing in.
/// </summary>
public static class SessionCookieEvents
{
    public static void Configure(CookieAuthenticationOptions options)
    {
        var toLogin = options.Events.OnRedirectToLogin;
        options.Events.OnRedirectToLogin = context =>
        {
            if (WantsJson(context.Request))
                return Status(context, StatusCodes.Status401Unauthorized);
            if (!HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method))
                context.RedirectUri = UriHelper.BuildAbsolute(context.Request.Scheme, context.Request.Host,
                    context.Request.PathBase, context.Options.LoginPath);
            return toLogin(context);
        };
        var toAccessDenied = options.Events.OnRedirectToAccessDenied;
        options.Events.OnRedirectToAccessDenied = context =>
            WantsJson(context.Request) ? Status(context, StatusCodes.Status403Forbidden) : toAccessDenied(context);
    }

    private static bool WantsJson(HttpRequest request) =>
        request.Headers.Accept.ToString().Contains("application/json", StringComparison.OrdinalIgnoreCase);

    private static Task Status(RedirectContext<CookieAuthenticationOptions> context, int status)
    {
        context.Response.StatusCode = status;
        return Task.CompletedTask;
    }
}

/// <summary>
/// The sign-in form of a tab can be outdated: its antiforgery token belongs to a visitor without sign-in, but the
/// session was signed in from another tab meanwhile (or the antiforgery cookie is gone). Instead of an empty 400 page
/// the visitor is sent back to the sign-in page (nothing was changed), which opens the running session if there is one.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class ReloadOutdatedSignInFormAttribute : Attribute, IAlwaysRunResultFilter
{
    public void OnResultExecuting(ResultExecutingContext context)
    {
        if (context.Result is not IAntiforgeryValidationFailedResult)
            return;
        var http = context.HttpContext;
        // Saved here: the filter that normally saves TempData does not run when a request is rejected this early.
        var tempData = http.RequestServices.GetRequiredService<ITempDataDictionaryFactory>().GetTempData(http);
        tempData["Error"] = http.User.Identity?.IsAuthenticated == true
            ? "Nobody was signed in: this session already belongs to the account shown here. " +
              "Use 'Sign in another account' in the account menu."
            : "The sign-in page was outdated. Please sign in again.";
        tempData.Save();
        context.Result = new RedirectToActionResult("Login", "Account", null);
    }

    public void OnResultExecuted(ResultExecutedContext context)
    {
    }
}
