using LogAnalyzer.Web.Models;
using Microsoft.AspNetCore.Identity;

namespace LogAnalyzer.Web.Services;

/// <summary>Identity hook: accounts disabled by an administrator are not allowed to sign in.</summary>
public sealed class EnabledUserConfirmation : IUserConfirmation<AppUser>
{
    public Task<bool> IsConfirmedAsync(UserManager<AppUser> manager, AppUser user) => Task.FromResult(!user.IsDisabled);
}
