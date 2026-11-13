using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

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
    })
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

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

// Every page requires login unless marked [AllowAnonymous].
var requireAuth = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
builder.Services.AddControllersWithViews(options => options.Filters.Add(new AuthorizeFilter(requireAuth)));

// Log ingestion: parser, file storage and background processing queue
builder.Services.AddSingleton<ILogParser, CombinedLogParser>();
builder.Services.AddSingleton<LogFileStorage>();
builder.Services.AddSingleton<LogProcessingQueue>();
builder.Services.AddHostedService<LogProcessingWorker>();

// Detection and evaluation
builder.Services.AddScoped<DetectionEngine>();
builder.Services.AddScoped<EvaluationService>();

// IP enrichment, dashboard and reports
builder.Services.AddSingleton<GeoIpLookup>();
builder.Services.AddHttpClient<AbuseIpDbClient>(c => c.Timeout = TimeSpan.FromSeconds(10));
builder.Services.AddScoped<IpEnrichmentService>();
builder.Services.AddScoped<DashboardService>();
builder.Services.AddScoped<ReportService>();
QuestPDF.Settings.License = QuestPDF.Infrastructure.LicenseType.Community;

var app = builder.Build();

// Skip DB setup when EF Core tools (Add-Migration) load the app.
if (!EF.IsDesignTime)
    await DbSeeder.SeedAsync(app.Services);

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
