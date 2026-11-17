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
/// Admin-only account management (FR1): create, edit (name, role, SOC tier), disable/enable, unlock, reset password
/// and delete. Disable suspends an account; delete removes it for good while uploads, alerts and the audit trail stay.
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
            Tier = model.Role == Roles.Analyst ? model.Tier ?? AnalystTier.Soc1 : null,
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

        await audit.WriteAsync("User.Create", user.Email, $"role {model.Role}{(user.Tier is { } t ? " " + SocPermissions.Label(t) : "")}");
        logger.LogInformation("User {Admin} created account {Email} ({Role})", User.Identity?.Name, user.Email, model.Role);
        TempData["Success"] = $"Account {user.Email} created as {model.Role}.";
        return RedirectToAction(nameof(Index));
    }

    [HttpGet]
    public async Task<IActionResult> Edit(string id)
    {
        var user = await userManager.FindByIdAsync(id);
        if (user is null)
            return NotFound();
        var role = (await userManager.GetRolesAsync(user)).OrderBy(r => r).FirstOrDefault() ?? Roles.Analyst;
        ViewBag.Roles = AllRoles;
        return View(new EditUserModel
        {
            Id = user.Id,
            Email = user.Email ?? string.Empty,
            FullName = user.FullName,
            Role = role,
            Tier = user.Tier ?? AnalystTier.Soc1,
            IsSelf = user.Id == userManager.GetUserId(User)
        });
    }

    /// <summary>Saves name, role and SOC tier. Admins cannot change their own role (no accidental self-lock-out).</summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(string id, EditUserModel model)
    {
        await AdminStateLock.WaitAsync();
        try { return await EditLockedAsync(id, model); }
        finally { AdminStateLock.Release(); }
    }

    private async Task<IActionResult> EditLockedAsync(string id, EditUserModel model)
    {
        var user = await userManager.FindByIdAsync(id);
        if (user is null)
            return NotFound();
        var isSelf = user.Id == userManager.GetUserId(User);
        var currentRoles = await userManager.GetRolesAsync(user);
        var currentRole = currentRoles.OrderBy(r => r).FirstOrDefault() ?? Roles.Analyst;

        model.Id = user.Id;
        model.Email = user.Email ?? string.Empty;
        model.IsSelf = isSelf;
        ViewBag.Roles = AllRoles;
        if (!AllRoles.Contains(model.Role))
            ModelState.AddModelError(nameof(model.Role), "Unknown role.");
        if (isSelf && model.Role != currentRole)
            ModelState.AddModelError(nameof(model.Role), "You cannot change your own role.");
        if (model.Role != Roles.Admin && currentRole == Roles.Admin && await IsLastActiveAdminAsync(user))
            ModelState.AddModelError(nameof(model.Role), "This is the last active administrator.");
        if (!ModelState.IsValid)
            return View(model);

        var newTier = model.Role == Roles.Analyst ? model.Tier ?? AnalystTier.Soc1 : (AnalystTier?)null;
        var changes = new List<string>();
        if (user.FullName != model.FullName.Trim())
            changes.Add($"name \"{user.FullName}\" -> \"{model.FullName.Trim()}\"");
        if (currentRole != model.Role)
            changes.Add($"role {currentRole} -> {model.Role}");
        if (user.Tier != newTier)
            changes.Add($"tier {TierText(user.Tier)} -> {TierText(newTier)}");
        if (changes.Count == 0)
        {
            TempData["Success"] = "Nothing changed.";
            return RedirectToAction(nameof(Index));
        }

        user.FullName = model.FullName.Trim();
        user.Tier = newTier;
        await userManager.UpdateAsync(user);
        if (currentRole != model.Role)
        {
            await userManager.RemoveFromRolesAsync(user, currentRoles);
            await userManager.AddToRoleAsync(user, model.Role);
            await userManager.UpdateSecurityStampAsync(user); // forces a fresh sign-in with the new role
        }

        await audit.WriteAsync("User.Edit", user.Email, string.Join("; ", changes));
        logger.LogInformation("User {Admin} edited account {Email}: {Changes}", User.Identity?.Name, user.Email, string.Join("; ", changes));
        TempData["Success"] = $"{user.Email} saved ({string.Join(", ", changes)}).";
        return RedirectToAction(nameof(Index));
    }

    /// <summary>
    /// Removes an account for good (e.g. someone left the organisation): the person can no longer sign in and open
    /// sessions end at their next request. History stays: uploaded files keep the uploader's e-mail, the audit log
    /// keeps every entry, alerts they owned go back to the queue (unassigned).
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(string id, string? confirmEmail)
    {
        await AdminStateLock.WaitAsync();
        try { return await DeleteLockedAsync(id, confirmEmail); }
        finally { AdminStateLock.Release(); }
    }

    private async Task<IActionResult> DeleteLockedAsync(string id, string? confirmEmail)
    {
        var user = await userManager.FindByIdAsync(id);
        if (user is null)
            return NotFound();
        if (user.Id == userManager.GetUserId(User))
            return Fail("You cannot delete your own account.");
        if (!string.Equals(confirmEmail?.Trim(), user.Email, StringComparison.OrdinalIgnoreCase))
            return Fail($"Not deleted: type the e-mail address {user.Email} to confirm.");
        if (await IsLastActiveAdminAsync(user))
            return Fail("This is the last active administrator.");

        var roles = string.Join(",", await userManager.GetRolesAsync(user));
        var files = await db.LogFiles.CountAsync(f => f.UploadedById == user.Id);
        // Keep who uploaded each file (the foreign key becomes null when the account is removed).
        await db.LogFiles.Where(f => f.UploadedById == user.Id && f.UploadedByName == null)
            .ExecuteUpdateAsync(s => s.SetProperty(f => f.UploadedByName, user.Email));
        var unassigned = await db.Alerts.Where(a => a.AssignedToId == user.Id)
            .ExecuteUpdateAsync(s => s.SetProperty(a => a.AssignedToId, (string?)null));

        var result = await userManager.DeleteAsync(user);
        if (!result.Succeeded)
            return Fail("Account not deleted: " + string.Join(" ", result.Errors.Select(e => e.Description)));

        var details = $"role {roles}{(user.Tier is { } t ? " " + SocPermissions.Label(t) : "")}; " +
                      $"{files} uploaded file(s) kept; {unassigned} alert(s) unassigned";
        await audit.WriteAsync("User.Delete", user.Email, details);
        logger.LogWarning("User {Admin} deleted account {Email} ({Details})", User.Identity?.Name, user.Email, details);
        TempData["Success"] = $"{user.Email} deleted. {files} uploaded file(s) and the audit history are kept; " +
                              $"{unassigned} alert(s) went back to the queue.";
        return RedirectToAction(nameof(Index));
    }

    private static string TierText(AnalystTier? tier) => tier is { } t ? SocPermissions.Label(t) : "none";

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
