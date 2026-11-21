using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;

var builder = WebApplication.CreateBuilder(args);

// "Demo" = the jury presentation profile: production error handling (no stack traces), but local settings
// (appsettings.Demo.json) and the developer's user-secrets (API keys) like in Development.
if (builder.Environment.IsEnvironment("Demo"))
    builder.Configuration.AddUserSecrets(typeof(Program).Assembly, optional: true);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services
    .AddIdentity<AppUser, IdentityRole>(options =>
    {
        options.Password.RequiredLength = 10;
        options.Password.RequireNonAlphanumeric = true;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
        options.User.RequireUniqueEmail = true;
        // "Confirmed" = not disabled by an administrator (see EnabledUserConfirmation).
        options.SignIn.RequireConfirmedAccount = true;
    })
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders()
    .AddClaimsPrincipalFactory<AppUserClaimsPrincipalFactory>();
builder.Services.AddScoped<IUserConfirmation<AppUser>, EnabledUserConfirmation>();

// Re-check the security stamp every minute, so disabling a user or changing a role takes effect quickly.
builder.Services.Configure<SecurityStampValidatorOptions>(o => o.ValidationInterval = TimeSpan.FromMinutes(1));

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.SlidingExpiration = true;
});

// Session slots (/s/1 ... /s/9): every slot has its own Identity cookies, so several accounts can be signed in at
// the same time in one browser, one per tab (see SessionSlots). The path is always "/" (the default would be the
// path base, i.e. "/s/2", and a slot cookie could then shadow another one with the same name).
foreach (var scheme in new[] { IdentityConstants.ApplicationScheme, IdentityConstants.ExternalScheme,
             IdentityConstants.TwoFactorUserIdScheme, IdentityConstants.TwoFactorRememberMeScheme })
{
    builder.Services.Configure<CookieAuthenticationOptions>(scheme, options =>
    {
        options.CookieManager = new SessionSlotCookieManager();
        options.Cookie.Path = "/";
    });
}
// One antiforgery cookie for all slots (path "/"); the form tokens are bound to the user signed in in that slot.
builder.Services.AddAntiforgery(options => options.Cookie.Path = "/");

// Every page requires login unless marked [AllowAnonymous].
var requireAuth = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(new AuthorizeFilter(requireAuth));
    options.Filters.Add(new RequirePasswordChangeFilter());
    options.Filters.Add<RevalidateSessionFilter>();
    // Every POST/PUT/DELETE needs a valid antiforgery token, also on actions that forget the attribute.
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
});
// TempData messages in a cookie per session slot (replaces MVC's CookieTempDataProvider).
builder.Services.Replace(ServiceDescriptor.Singleton<ITempDataProvider, SessionSlotTempDataProvider>());

// Behind a reverse proxy: trust X-Forwarded-For/-Proto only from the proxies listed in configuration
// (ForwardedHeaders:KnownProxies), so rate limiting and the audit log see the real client address.
var knownProxies = builder.Configuration.GetSection("ForwardedHeaders:KnownProxies").Get<string[]>() ?? [];
if (knownProxies.Length > 0)
{
    builder.Services.Configure<ForwardedHeadersOptions>(options =>
    {
        options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        options.KnownIPNetworks.Clear();
        options.KnownProxies.Clear();
        foreach (var proxy in knownProxies)
            options.KnownProxies.Add(System.Net.IPAddress.Parse(proxy));
    });
}

// Login throttling per client IP (on top of the per-account lockout): 10 attempts per minute.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("login", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ClientNetwork.RateLimitKey(ctx.Connection.RemoteIpAddress),
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
    // Live threat-intel lookups per signed-in user, so nobody can burn the free API quotas in a loop.
    options.AddPolicy("ti-lookup", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.User.Identity?.Name ?? ClientNetwork.RateLimitKey(ctx.Connection.RemoteIpAddress),
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 30, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
});

// Audit trail of user actions
builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton<IAuditLog, AuditLog>();

// Log ingestion: parser, file storage and background processing queue
builder.Services.AddSingleton<ILogParser, CombinedLogParser>();
builder.Services.AddSingleton<LogFileStorage>();
builder.Services.Configure<ProcessingOptions>(builder.Configuration.GetSection(ProcessingOptions.Section));
builder.Services.AddSingleton<LogProcessingQueue>();
builder.Services.AddHostedService<LogProcessingWorker>();

// Detection and evaluation
builder.Services.AddSingleton<AnomalyDetector>();
builder.Services.AddScoped<DetectionEngine>();
builder.Services.AddScoped<RuleTester>();
builder.Services.AddScoped<EvaluationService>();

// IP enrichment: offline GeoIP + threat-intel providers (API keys in user-secrets, see README)
builder.Services.Configure<EnrichmentOptions>(builder.Configuration.GetSection(EnrichmentOptions.Section));
builder.Services.AddSingleton<GeoIpLookup>();
builder.Services.AddScoped<IpEnrichmentService>();
builder.Services.AddSingleton<ProviderThrottle>();
// No redirects (the API key headers would be sent to the new host) and at most 1 MB per answer.
static SocketsHttpHandler ProviderHandler() => new() { AllowAutoRedirect = false, PooledConnectionLifetime = TimeSpan.FromMinutes(5) };
builder.Services.AddHttpClient<AbuseIpDbProvider>(c => { c.Timeout = TimeSpan.FromSeconds(10); c.MaxResponseContentBufferSize = 1_000_000; })
    .ConfigurePrimaryHttpMessageHandler(ProviderHandler);
builder.Services.AddHttpClient<GreyNoiseProvider>(c => { c.Timeout = TimeSpan.FromSeconds(10); c.MaxResponseContentBufferSize = 1_000_000; })
    .ConfigurePrimaryHttpMessageHandler(ProviderHandler);
builder.Services.AddHttpClient<VirusTotalProvider>(c => { c.Timeout = TimeSpan.FromSeconds(15); c.MaxResponseContentBufferSize = 1_000_000; })
    .ConfigurePrimaryHttpMessageHandler(ProviderHandler);
builder.Services.AddTransient<IThreatIntelProvider>(sp => sp.GetRequiredService<AbuseIpDbProvider>());
builder.Services.AddTransient<IThreatIntelProvider>(sp => sp.GetRequiredService<GreyNoiseProvider>());
builder.Services.AddTransient<IThreatIntelProvider>(sp => sp.GetRequiredService<VirusTotalProvider>());
// Vendors added 2026-11-18 (inactive until their key is set in user-secrets)
builder.Services.AddHttpClient<GtiProvider>(c => { c.Timeout = TimeSpan.FromSeconds(15); c.MaxResponseContentBufferSize = 1_000_000; })
    .ConfigurePrimaryHttpMessageHandler(ProviderHandler);
builder.Services.AddHttpClient<RecordedFutureProvider>(c => { c.Timeout = TimeSpan.FromSeconds(15); c.MaxResponseContentBufferSize = 1_000_000; })
    .ConfigurePrimaryHttpMessageHandler(ProviderHandler);
builder.Services.AddHttpClient<OtxProvider>(c => { c.Timeout = TimeSpan.FromSeconds(15); c.MaxResponseContentBufferSize = 1_000_000; })
    .ConfigurePrimaryHttpMessageHandler(ProviderHandler);
builder.Services.AddHttpClient<ThreatFoxProvider>(c => { c.Timeout = TimeSpan.FromSeconds(15); c.MaxResponseContentBufferSize = 1_000_000; })
    .ConfigurePrimaryHttpMessageHandler(ProviderHandler);
builder.Services.AddHttpClient<UrlhausProvider>(c => { c.Timeout = TimeSpan.FromSeconds(15); c.MaxResponseContentBufferSize = 1_000_000; })
    .ConfigurePrimaryHttpMessageHandler(ProviderHandler);
builder.Services.AddHttpClient<MalwareBazaarProvider>(c => { c.Timeout = TimeSpan.FromSeconds(15); c.MaxResponseContentBufferSize = 1_000_000; })
    .ConfigurePrimaryHttpMessageHandler(ProviderHandler);
builder.Services.AddTransient<IThreatIntelProvider>(sp => sp.GetRequiredService<GtiProvider>());
builder.Services.AddTransient<IThreatIntelProvider>(sp => sp.GetRequiredService<RecordedFutureProvider>());
builder.Services.AddTransient<IThreatIntelProvider>(sp => sp.GetRequiredService<OtxProvider>());
builder.Services.AddTransient<IThreatIntelProvider>(sp => sp.GetRequiredService<ThreatFoxProvider>());
builder.Services.AddTransient<IThreatIntelProvider>(sp => sp.GetRequiredService<UrlhausProvider>());
builder.Services.AddTransient<IThreatIntelProvider>(sp => sp.GetRequiredService<MalwareBazaarProvider>());
builder.Services.AddScoped<ThreatIntelService>();
builder.Services.AddScoped<ILogFileThreatIntel>(sp => sp.GetRequiredService<ThreatIntelService>());
builder.Services.AddSingleton<ThreatIntelQueue>();
builder.Services.AddHostedService<ThreatIntelWorker>();
builder.Services.AddHostedService<DataRetentionWorker>();

// Dashboard and reports
builder.Services.AddScoped<DashboardService>();
builder.Services.AddScoped<ReportService>();
builder.Services.AddScoped<NotificationService>();
QuestPDF.Settings.License = QuestPDF.Infrastructure.LicenseType.Community;

var app = builder.Build();

// Visual Studio (F5): hide the log console so it cannot be closed by accident; logs stay in the Output window.
ConsoleWindow.HideWhenDebuggedByVisualStudio(app.Lifetime, app.Logger);

// Skip DB setup when EF Core tools (Add-Migration) load the app.
if (!EF.IsDesignTime)
    await DbSeeder.SeedAsync(app.Services);

if (knownProxies.Length > 0)
    app.UseForwardedHeaders();

// First: "/s/{1-9}/..." → session slot n, the prefix becomes the path base (links, redirects and cookies follow it).
app.UseMiddleware<SessionSlotMiddleware>();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseRateLimiter();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
