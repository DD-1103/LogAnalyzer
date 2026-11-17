using System.Security.Claims;
using LogAnalyzer.Web.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;

namespace LogAnalyzer.Web.Services;

/// <summary>Adds a claim to the sign-in cookie when the user still has to choose a new password.</summary>
public class AppUserClaimsPrincipalFactory(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager,
    IOptions<IdentityOptions> options) : UserClaimsPrincipalFactory<AppUser, IdentityRole>(userManager, roleManager, options)
{
    public const string MustChangePasswordClaim = "la:must_change_password";

    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(AppUser user)
    {
        var identity = await base.GenerateClaimsAsync(user);
        if (user.MustChangePassword)
            identity.AddClaim(new Claim(MustChangePasswordClaim, "true"));
        return identity;
    }
}

/// <summary>
/// Sends users with a temporary password (seeded accounts, passwords set by an administrator) to "Change password"
/// before they can use anything else. Only the Account pages (change password, logout) and the error page stay open.
/// </summary>
public class RequirePasswordChangeFilter : IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var user = context.HttpContext.User;
        if (user.Identity?.IsAuthenticated != true || !user.HasClaim(AppUserClaimsPrincipalFactory.MustChangePasswordClaim, "true"))
            return;

        var controller = (context.ActionDescriptor as ControllerActionDescriptor)?.ControllerName;
        var action = (context.ActionDescriptor as ControllerActionDescriptor)?.ActionName;
        if (controller == "Account" || (controller == "Home" && action == "Error"))
            return;

        // Background requests (nav badges) get a plain 403 instead of an HTML redirect.
        if (context.HttpContext.Request.Headers.Accept.ToString().Contains("application/json", StringComparison.OrdinalIgnoreCase))
        {
            context.Result = new StatusCodeResult(StatusCodes.Status403Forbidden);
            return;
        }
        context.Result = new RedirectToActionResult("ChangePassword", "Account", null);
    }
}
