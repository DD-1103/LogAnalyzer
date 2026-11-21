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
        // Web rules first: on a new database the firewall rules below must not count as "rules already exist".
        if (!await db.DetectionRules.AnyAsync(r => r.Kind != RuleKind.Anomaly && r.AppliesTo == LogSource.WebAccess))
        {
            db.DetectionRules.AddRange(DefaultRules());
            await db.SaveChangesAsync();
        }

        // Firewall rules: added once to new and existing databases (when there is no firewall rule yet). A name that
        // is already taken is skipped, so rules an admin created or edited are never overwritten.
        if (!await db.DetectionRules.AnyAsync(r => r.AppliesTo == LogSource.Firewall))
        {
            var missing = FirewallRulesToSeed(await db.DetectionRules.Select(r => r.Name).ToListAsync());
            if (missing.Count > 0)
            {
                db.DetectionRules.AddRange(missing);
                await db.SaveChangesAsync();
                logger.LogInformation("Added {Count} default firewall detection rules", missing.Count);
            }
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

    /// <summary>The default firewall rules whose name is not taken yet (names compare case-insensitively).</summary>
    public static List<DetectionRule> FirewallRulesToSeed(IEnumerable<string> existingNames)
    {
        var names = existingNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return DefaultFirewallRules().Where(r => !names.Contains(r.Name)).ToList();
    }

    /// <summary>Ports of remote-access and database services that are typical brute-force targets.</summary>
    public const string RemoteAccessPorts = "21,22,23,139,445,1433,3306,3389,5432,5900";

    /// <summary>Ports typical for backdoors, reverse shells, IRC botnets, Tor and crypto-mining pools.</summary>
    public const string BackdoorPorts = "1337,4444,5555,6666,6667,6697,9001,9050,12345,31337,3333,14444";

    /// <summary>
    /// The seven built-in firewall rules (seeded once, also used by the unit tests). The reasoning behind each
    /// threshold is in the description, which the rules page shows.
    /// </summary>
    public static IEnumerable<DetectionRule> DefaultFirewallRules() =>
    [
        new()
        {
            Name = "Port scan",
            Description = "One source tries 15 or more different destination ports within 60 seconds, whether the firewall " +
                          "allowed or blocked them. Normal clients use a handful of ports (web, DNS, mail); tools like nmap " +
                          "or masscan probe dozens to thousands per minute, so 15 leaves a wide margin for normal traffic.",
            AppliesTo = LogSource.Firewall, AttackType = AttackType.PortScan, Severity = Severity.High,
            Kind = RuleKind.DistinctCount, Field = RuleField.DestinationPort,
            Threshold = 15, WindowSeconds = 60
        },
        new()
        {
            Name = "Network sweep",
            Description = "One source contacts 20 or more different destination hosts within 2 minutes (host discovery or " +
                          "worm-like spreading, e.g. ping sweeps or probing port 445 across a subnet). Busy servers such as " +
                          "proxies, DNS resolvers or NAT gateways legitimately talk to many hosts: review their alerts or raise the threshold.",
            AppliesTo = LogSource.Firewall, AttackType = AttackType.NetworkSweep, Severity = Severity.High,
            Kind = RuleKind.DistinctCount, Field = RuleField.DestinationIp,
            Threshold = 20, WindowSeconds = 120
        },
        new()
        {
            Name = "Brute force on remote-access services",
            Description = "20 or more connections from one source to remote-access or database ports (FTP, SSH, Telnet, SMB, " +
                          "MS SQL, MySQL, RDP, PostgreSQL, VNC) within 5 minutes. Each password guess is usually a new " +
                          "connection, while an administrator opens only a few sessions in that time. A sweep of one of " +
                          "these ports across many hosts triggers it as well (then the Network sweep alert explains it).",
            AppliesTo = LogSource.Firewall, AttackType = AttackType.BruteForce, Severity = Severity.High,
            Kind = RuleKind.Threshold, Field = RuleField.Message, PortFilter = RemoteAccessPorts,
            Threshold = 20, WindowSeconds = 300
        },
        new()
        {
            Name = "Flood of blocked connections",
            Description = "100 or more denied, dropped or rejected connections from one source within 60 seconds: flooding or " +
                          "persistent probing that the firewall stopped. A few blocked packets per minute are normal internet " +
                          "background noise, so the threshold is high.",
            AppliesTo = LogSource.Firewall, AttackType = AttackType.BlockedTraffic, Severity = Severity.Medium,
            Kind = RuleKind.Threshold, Field = RuleField.Message, ActionFilter = "Deny,Drop,Reject",
            Threshold = 100, WindowSeconds = 60
        },
        new()
        {
            Name = "Intrusion prevention / threat event",
            Description = "The firewall's own IPS, antivirus or botnet engine named a threat. These events are already the " +
                          "result of a vendor signature, so every one counts; all threat events of one source form one alert.",
            AppliesTo = LogSource.Firewall, AttackType = AttackType.Intrusion, Severity = Severity.High,
            Kind = RuleKind.Signature, Field = RuleField.ThreatName, Pattern = ".+"
        },
        new()
        {
            Name = "Connection to backdoor / C2 port",
            Description = "A connection to a port typical for backdoors and command-and-control: 4444 (Metasploit), 1337 and " +
                          "31337 (Back Orifice), 12345 (NetBus), 5555, 6666-6667 and 6697 (IRC botnets), 9001 and 9050 (Tor), " +
                          "3333 and 14444 (crypto-mining pools). Legitimate software rarely uses them, so one connection is enough.",
            AppliesTo = LogSource.Firewall, AttackType = AttackType.SuspiciousOutbound, Severity = Severity.Medium,
            Kind = RuleKind.Threshold, Field = RuleField.Message, PortFilter = BackdoorPorts,
            Threshold = 1, WindowSeconds = 60
        },
        new()
        {
            Name = "Repeated failed logins on the firewall / VPN",
            Description = "5 or more refused VPN or administrator logins from one source within 5 minutes (password guessing " +
                          "against the firewall itself). A user who mistypes a password fails once or twice, not five times.",
            AppliesTo = LogSource.Firewall, AttackType = AttackType.AuthenticationFailure, Severity = Severity.High,
            Kind = RuleKind.Threshold, Field = RuleField.EventType, Pattern = "(?i)^auth$", ActionFilter = "Deny,Reject",
            Threshold = 5, WindowSeconds = 300
        }
    ];
}
