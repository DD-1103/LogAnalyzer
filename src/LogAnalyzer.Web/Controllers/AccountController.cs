using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace LogAnalyzer.Web.Controllers;

public class AccountController(
    SignInManager<AppUser> signInManager,
    UserManager<AppUser> userManager,
    IAuditLog audit,
    ILogger<AccountController> logger) : Controller
{
    // Verified for unknown e-mail addresses so that they take as long as real ones (no account discovery by timing).
    private static readonly Lazy<string> DummyHash =
        new(() => new PasswordHasher<AppUser>().HashPassword(new AppUser(), Guid.NewGuid().ToString()));

    [AllowAnonymous]
    [HttpGet]
    public IActionResult Login(string? returnUrl = null) =>
        View(new LoginViewModel { ReturnUrl = returnUrl });

    [AllowAnonymous]
    [HttpPost]
    [ValidateAntiForgeryToken]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        var email = AuditLog.Clean(model.Email);
        var user = await userManager.FindByEmailAsync(model.Email);
        Microsoft.AspNetCore.Identity.SignInResult result;
        if (user is null)
        {
            userManager.PasswordHasher.VerifyHashedPassword(new AppUser(), DummyHash.Value, model.Password);
            result = Microsoft.AspNetCore.Identity.SignInResult.Failed;
        }
        else
        {
            result = await signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, lockoutOnFailure: true);
        }

        if (result.Succeeded)
        {
            user!.LastLoginAt = DateTime.UtcNow;
            await userManager.UpdateAsync(user);
            logger.LogInformation("User {Email} logged in", email);
            await audit.WriteAsync("Login.Success", email, null, email);
            return LocalRedirect(Url.IsLocalUrl(model.ReturnUrl) ? model.ReturnUrl! : "/");
        }

        // Unknown, wrong password, disabled and locked-out accounts all get the same message, so the page does not
        // reveal which accounts exist or that one is locked. The reason is only in the log and the audit trail.
        var reason = result.IsLockedOut ? "locked out" : result.IsNotAllowed ? "account disabled" : user is null ? "unknown account" : null;
        logger.LogWarning("Failed login for {Email} ({Reason})", email, reason ?? "wrong password");
        await audit.WriteAsync(result.IsLockedOut ? "Login.LockedOut" : "Login.Failed", email, reason, null);
        ModelState.AddModelError(string.Empty, "Invalid email or password.");
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await audit.WriteAsync("Logout", User.Identity?.Name);
        // New security stamp: copies of this sign-in cookie (and other sessions of the user) stop working too.
        if (await userManager.GetUserAsync(User) is { } user)
            await userManager.UpdateSecurityStampAsync(user);
        await signInManager.SignOutAsync();
        return RedirectToAction(nameof(Login));
    }

    [HttpGet]
    public IActionResult ChangePassword() => View(new ChangePasswordModel());

    [HttpPost]
    [ValidateAntiForgeryToken]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> ChangePassword(ChangePasswordModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        var user = await userManager.GetUserAsync(User);
        if (user is null)
            return Challenge();

        // Wrong current passwords count towards the account lockout, like failed logins (no guessing with a stolen cookie).
        var check = await signInManager.CheckPasswordSignInAsync(user, model.CurrentPassword, lockoutOnFailure: true);
        if (check.IsLockedOut)
        {
            logger.LogWarning("Account {Email} locked after wrong current passwords on Change password", user.Email);
            await audit.WriteAsync("User.ChangeOwnPassword.LockedOut", user.Email);
            await signInManager.SignOutAsync();
            return RedirectToAction(nameof(Login));
        }
        if (!check.Succeeded)
        {
            ModelState.AddModelError(nameof(model.CurrentPassword), "The current password is not correct.");
            return View(model);
        }

        var result = await userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
        if (!result.Succeeded)
        {
            foreach (var e in result.Errors)
                ModelState.AddModelError(string.Empty, e.Description);
            return View(model);
        }

        if (user.MustChangePassword)
        {
            user.MustChangePassword = false;
            await userManager.UpdateAsync(user);
        }
        await signInManager.RefreshSignInAsync(user);   // new cookie without the "must change password" claim
        await audit.WriteAsync("User.ChangeOwnPassword", user.Email);
        TempData["Success"] = "Your password was changed.";
        return RedirectToAction("Index", "Home");
    }

    [AllowAnonymous]
    [HttpGet]
    public IActionResult AccessDenied() => View();
}
