using LogAnalyzer.Web.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Data;

public static class Roles
{
    public const string Admin = "Admin";
    public const string Analyst = "Analyst";
}

public static class DbSeeder
{
    public static async Task SeedAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var sp = scope.ServiceProvider;
        var db = sp.GetRequiredService<AppDbContext>();
        var config = sp.GetRequiredService<IConfiguration>();
        var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("DbSeeder");

        // Applies any pending migrations (run Add-Migration first).
        await db.Database.MigrateAsync();

        // Roles
        var roleManager = sp.GetRequiredService<RoleManager<IdentityRole>>();
        foreach (var role in new[] { Roles.Admin, Roles.Analyst })
        {
            if (!await roleManager.RoleExistsAsync(role))
                await roleManager.CreateAsync(new IdentityRole(role));
        }

        // First admin account (credentials from configuration / user secrets)
        var userManager = sp.GetRequiredService<UserManager<AppUser>>();
        var email = config["SeedAdmin:Email"];
        var password = config["SeedAdmin:Password"];
        if (!string.IsNullOrWhiteSpace(email) && !string.IsNullOrWhiteSpace(password)
            && await userManager.FindByEmailAsync(email) is null)
        {
            var admin = new AppUser { UserName = email, Email = email, EmailConfirmed = true, FullName = "Administrator" };
            var result = await userManager.CreateAsync(admin, password);
            if (result.Succeeded)
                await userManager.AddToRoleAsync(admin, Roles.Admin);
            else
                logger.LogError("Could not create seed admin: {Errors}",
                    string.Join("; ", result.Errors.Select(e => e.Description)));
        }

        // Default detection rules
        if (!await db.DetectionRules.AnyAsync())
        {
            db.DetectionRules.AddRange(DefaultRules());
            await db.SaveChangesAsync();
        }
    }

    private static IEnumerable<DetectionRule> DefaultRules() =>
    [
        new()
        {
            Name = "SQL injection signatures",
            Description = "Common SQL injection payloads in the request URL.",
            AttackType = AttackType.SqlInjection, Severity = Severity.High, Kind = RuleKind.Signature,
            Field = RuleField.Url,
            Pattern = @"(?i)(union(\s|\+|%20)+(all(\s|\+|%20)+)?select|'\s*or\s*'?\d+'?\s*=\s*'?\d+|(\s|\+|%20)or(\s|\+|%20)+1=1|sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|information_schema|xp_cmdshell|;\s*drop\s+table|--\s*$)"
        },
        new()
        {
            Name = "XSS signatures",
            Description = "Script injection attempts in the request URL.",
            AttackType = AttackType.Xss, Severity = Severity.Medium, Kind = RuleKind.Signature,
            Field = RuleField.Url,
            Pattern = @"(?i)(<\s*script|%3c\s*script|javascript:|on(error|load|mouseover|focus)\s*=|<\s*img[^>]+src|alert\s*\(|document\.cookie)"
        },
        new()
        {
            Name = "Path traversal / LFI",
            Description = "Directory traversal and local file inclusion attempts.",
            AttackType = AttackType.PathTraversal, Severity = Severity.High, Kind = RuleKind.Signature,
            Field = RuleField.Url,
            Pattern = @"(?i)(\.\./|\.\.\\|%2e%2e(%2f|/|%5c)|/etc/passwd|/etc/shadow|boot\.ini|win\.ini|php://filter|/proc/self/environ)"
        },
        new()
        {
            Name = "Known scanner user agents",
            Description = "Requests from well-known automated attack and scanning tools.",
            AttackType = AttackType.Scanner, Severity = Severity.Medium, Kind = RuleKind.Signature,
            Field = RuleField.UserAgent,
            Pattern = @"(?i)(sqlmap|nikto|nmap|masscan|gobuster|dirbuster|wfuzz|ffuf|hydra|acunetix|nessus|openvas|zgrab|nuclei|wpscan)"
        },
        new()
        {
            Name = "Login brute force",
            Description = "Many POST requests to login endpoints from one IP in a short time.",
            AttackType = AttackType.BruteForce, Severity = Severity.High, Kind = RuleKind.Threshold,
            MethodFilter = "POST", PathPattern = @"(?i)(login|signin|wp-login\.php|auth|xmlrpc\.php)",
            Threshold = 20, WindowSeconds = 60
        },
        new()
        {
            Name = "Directory enumeration",
            Description = "High number of 404 responses from one IP in a short time.",
            AttackType = AttackType.DirectoryEnumeration, Severity = Severity.Medium, Kind = RuleKind.Threshold,
            StatusFilter = 404, Threshold = 50, WindowSeconds = 60
        }
    ];
}
