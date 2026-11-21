using System.Security.Claims;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
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
