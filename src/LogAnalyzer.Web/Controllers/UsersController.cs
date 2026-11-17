using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Controllers;

/// <summary>
/// Admin-only account management (FR1): create Admin/Analyst accounts, change role, disable/enable, reset password.
/// Accounts are never deleted, so alerts and audit entries stay attributable.
/// </summary>
[Authorize(Roles = Roles.Admin)]
public class UsersController(
    UserManager<AppUser> userManager,
    AppDbContext db,
    IAuditLog audit,
    ILogger<UsersController> logger) : Controller
{
    private static readonly string[] AllRoles = [Roles.Admin, Roles.Analyst];

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var users = await db.Users.AsNoTracking().OrderBy(u => u.Email).ToListAsync();
        var roles = await (from ur in db.UserRoles
                           join r in db.Roles on ur.RoleId equals r.Id
                           select new { ur.UserId, r.Name }).ToListAsync();
        var selfId = userManager.GetUserId(User);

        var rows = users.Select(u => new UserRow(
            u,
            roles.Where(r => r.UserId == u.Id).Select(r => r.Name!).OrderBy(n => n).FirstOrDefault() ?? "—",
            u.LockoutEnd > DateTimeOffset.UtcNow,
            u.Id == selfId)).ToList();
        ViewBag.Roles = AllRoles;
        return View(rows);
    }

    [HttpGet]
    public IActionResult Create()
    {
        ViewBag.Roles = AllRoles;
        return View(new CreateUserModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(CreateUserModel model)
    {
        ViewBag.Roles = AllRoles;
        if (!AllRoles.Contains(model.Role))
            ModelState.AddModelError(nameof(model.Role), "Unknown role.");
        if (!ModelState.IsValid)
            return View(model);

        var user = new AppUser
        {
            UserName = model.Email.Trim(),
            Email = model.Email.Trim(),
            EmailConfirmed = true,
            FullName = model.FullName.Trim(),
            LockoutEnabled = true,
            MustChangePassword = true   // the administrator knows this password
        };
        var result = await userManager.CreateAsync(user, model.Password);
        if (!result.Succeeded)
        {
            foreach (var e in result.Errors)
                ModelState.AddModelError(string.Empty, e.Description);
            return View(model);
        }
        await userManager.AddToRoleAsync(user, model.Role);

        await audit.WriteAsync("User.Create", user.Email, $"role {model.Role}");
        logger.LogInformation("User {Admin} created account {Email} ({Role})", User.Identity?.Name, user.Email, model.Role);
        TempData["Success"] = $"Account {user.Email} created as {model.Role}.";
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangeRole(string id, string role)
    {
        await AdminStateLock.WaitAsync();
        try { return await ChangeRoleLockedAsync(id, role); }
        finally { AdminStateLock.Release(); }
    }

    private async Task<IActionResult> ChangeRoleLockedAsync(string id, string role)
    {
        if (!AllRoles.Contains(role))
            return BadRequest();
        var user = await userManager.FindByIdAsync(id);
        if (user is null)
            return NotFound();
        if (user.Id == userManager.GetUserId(User))
            return Fail("You cannot change your own role.");
        if (role != Roles.Admin && await IsLastActiveAdminAsync(user))
            return Fail("This is the last active administrator.");

        var current = await userManager.GetRolesAsync(user);
        await userManager.RemoveFromRolesAsync(user, current);
        await userManager.AddToRoleAsync(user, role);
        await userManager.UpdateSecurityStampAsync(user); // forces a fresh sign-in with the new role

        await audit.WriteAsync("User.ChangeRole", user.Email, $"{string.Join(",", current)} -> {role}");
        TempData["Success"] = $"{user.Email} is now {role}.";
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ToggleDisabled(string id)
    {
        await AdminStateLock.WaitAsync();
        try { return await ToggleDisabledLockedAsync(id); }
        finally { AdminStateLock.Release(); }
    }

    private async Task<IActionResult> ToggleDisabledLockedAsync(string id)
    {
        var user = await userManager.FindByIdAsync(id);
        if (user is null)
            return NotFound();
        if (user.Id == userManager.GetUserId(User))
            return Fail("You cannot disable your own account.");
        if (!user.IsDisabled && await IsLastActiveAdminAsync(user))
            return Fail("This is the last active administrator.");

        user.IsDisabled = !user.IsDisabled;
        if (!user.IsDisabled)
        {
            user.LockoutEnd = null;
            user.AccessFailedCount = 0;
        }
        await userManager.UpdateAsync(user);
        await userManager.UpdateSecurityStampAsync(user); // signs the user out of existing sessions

        await audit.WriteAsync(user.IsDisabled ? "User.Disable" : "User.Enable", user.Email);
        logger.LogInformation("User {Admin} {Action} account {Email}", User.Identity?.Name,
            user.IsDisabled ? "disabled" : "enabled", user.Email);
        TempData["Success"] = $"{user.Email} {(user.IsDisabled ? "disabled" : "enabled")}.";
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Unlock(string id)
    {
        var user = await userManager.FindByIdAsync(id);
        if (user is null)
            return NotFound();
        await userManager.SetLockoutEndDateAsync(user, null);
        await userManager.ResetAccessFailedCountAsync(user);
        await audit.WriteAsync("User.Unlock", user.Email);
        TempData["Success"] = $"{user.Email} unlocked.";
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(string id, string newPassword)
    {
        var user = await userManager.FindByIdAsync(id);
        if (user is null)
            return NotFound();

        var token = await userManager.GeneratePasswordResetTokenAsync(user);
        var result = await userManager.ResetPasswordAsync(user, token, newPassword ?? string.Empty);
        if (!result.Succeeded)
            return Fail("Password not changed: " + string.Join(" ", result.Errors.Select(e => e.Description)));

        user.MustChangePassword = true;   // the administrator knows the new password
        await userManager.UpdateAsync(user);
        await userManager.UpdateSecurityStampAsync(user);
        await audit.WriteAsync("User.ResetPassword", user.Email);
        logger.LogInformation("User {Admin} reset the password of {Email}", User.Identity?.Name, user.Email);
        TempData["Success"] = $"Password of {user.Email} reset. Give it to the user over a safe channel; they must choose a new one at the next login.";
        return RedirectToAction(nameof(Index));
    }

    /// <summary>
    /// Role and enable/disable changes run one at a time, so two administrators cannot disable or demote each other
    /// at the same moment and leave the application without an active administrator.
    /// </summary>
    private static readonly SemaphoreSlim AdminStateLock = new(1, 1);

    private async Task<bool> IsLastActiveAdminAsync(AppUser user) =>
        IsLastActiveAdmin(user, await userManager.IsInRoleAsync(user, Roles.Admin),
            await userManager.GetUsersInRoleAsync(Roles.Admin));

    /// <summary>
    /// True when demoting or disabling <paramref name="target"/> would leave no active administrator.
    /// A disabled admin is not active, so changing it never counts (it could not be demoted before the fix).
    /// </summary>
    public static bool IsLastActiveAdmin(AppUser target, bool targetIsAdmin, IEnumerable<AppUser> admins) =>
        targetIsAdmin && !target.IsDisabled && admins.Count(a => !a.IsDisabled && a.Id != target.Id) == 0;

    private RedirectToActionResult Fail(string message)
    {
        TempData["Error"] = message;
        return RedirectToAction(nameof(Index));
    }
}
