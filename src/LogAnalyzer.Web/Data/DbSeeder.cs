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

        // Apply new migrations only when there are any. Checking first keeps normal start-ups quiet and fast
        // (MigrateAsync always takes a database lock and logs "Acquiring an exclusive lock for migration application").
        // Database:MigrateOnStartup = false: the app account needs no DDL rights; run `dotnet ef database update`
        // (or a migration script) with a separate admin account instead.
        var pending = (await db.Database.GetPendingMigrationsAsync()).ToList();
        if (pending.Count > 0)
        {
            if (!config.GetValue("Database:MigrateOnStartup", true))
            {
                logger.LogCritical("The database is missing migrations ({Migrations}) and Database:MigrateOnStartup is off. " +
                                   "Apply them with an account that has DDL rights.", string.Join(", ", pending));
                throw new InvalidOperationException("Database schema is out of date.");
            }
            logger.LogInformation("Updating the database: {Migrations}", string.Join(", ", pending));
            await db.Database.MigrateAsync();
        }

        // Roles
        var roleManager = sp.GetRequiredService<RoleManager<IdentityRole>>();
        foreach (var role in new[] { Roles.Admin, Roles.Analyst })
        {
            if (!await roleManager.RoleExistsAsync(role))
                await roleManager.CreateAsync(new IdentityRole(role));
        }

        // First admin account and, in development, a demo analyst account. E-mail and password come from
        // user-secrets or environment variables (SeedAdmin__Email / SeedAdmin__Password), never from files in git.
        // Created only if missing, never overwritten; the user must choose a new password at the first login.
        var userManager = sp.GetRequiredService<UserManager<AppUser>>();
        await SeedUserAsync(userManager, config, "SeedAdmin", "Administrator", Roles.Admin, logger);
        if (sp.GetRequiredService<IHostEnvironment>().IsDevelopment())
            await SeedUserAsync(userManager, config, "SeedAnalyst", "Demo Analyst", Roles.Analyst, logger);

        if ((await userManager.GetUsersInRoleAsync(Roles.Admin)).Count == 0)
            logger.LogWarning("There is no administrator account. Set SeedAdmin:Email and SeedAdmin:Password " +
                              "(user-secrets or the environment variables SeedAdmin__Email / SeedAdmin__Password) and restart.");

        // Default detection rules
        // (The Isolation Forest anomaly rule is inserted by the AnomalyDetection migration.)
        if (!await db.DetectionRules.AnyAsync(r => r.Kind != RuleKind.Anomaly))
        {
            db.DetectionRules.AddRange(DefaultRules());
            await db.SaveChangesAsync();
        }
    }

    private static async Task SeedUserAsync(UserManager<AppUser> userManager, IConfiguration config,
        string section, string fullName, string role, ILogger logger)
    {
        var email = config[$"{section}:Email"];
        var password = config[$"{section}:Password"];
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password)
            || await userManager.FindByEmailAsync(email) is not null)
            return;

        var user = new AppUser
        {
            UserName = email, Email = email, EmailConfirmed = true, FullName = fullName, MustChangePassword = true
        };
        var result = await userManager.CreateAsync(user, password);
        if (result.Succeeded)
            await userManager.AddToRoleAsync(user, role);
        else
            logger.LogError("Could not create seed user {Section}: {Errors}", section,
                string.Join("; ", result.Errors.Select(e => e.Description)));
    }

    /// <summary>The six built-in rules (also used by the benchmark tool and the unit tests).</summary>
    public static IEnumerable<DetectionRule> DefaultRules() =>
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
