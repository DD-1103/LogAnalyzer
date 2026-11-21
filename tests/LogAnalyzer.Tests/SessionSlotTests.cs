using System.Diagnostics;
using System.Security.Claims;
using LogAnalyzer.Web.Services;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures.Infrastructure;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace LogAnalyzer.Tests;

/// <summary>Session slots: several accounts signed in at the same time in one browser (/s/1 ... /s/9).</summary>
public class SessionSlotTests
{
    private const string AuthCookie = ".AspNetCore.Identity.Application";

    // ---------------------------------------------------------------- middleware

    [Theory]
    [InlineData("/s/2/Alerts", "", "/s/2", "/Alerts", 2)]
    [InlineData("/s/2", "", "/s/2", "/", 2)]
    [InlineData("/s/2/", "", "/s/2", "/", 2)]
    [InlineData("/s/1/Alerts/Details/5", "", "/s/1", "/Alerts/Details/5", 1)]
    [InlineData("/s/9/css/site.css", "", "/s/9", "/css/site.css", 9)]
    [InlineData("/s/3/Alerts", "/app", "/app/s/3", "/Alerts", 3)]
    public async Task Middleware_MovesSlotPrefixIntoPathBase(string path, string pathBase, string expectedBase, string expectedPath, int slot)
    {
        var context = new DefaultHttpContext();
        context.Request.PathBase = pathBase;
        context.Request.Path = path;
        context.Request.QueryString = new QueryString("?q=1%2F2&x=%2Fs%2F2");
        (string? Base, string? Path, int Slot, string Query, PathString Root) seen = default;

        await new SessionSlotMiddleware(ctx =>
        {
            seen = (ctx.Request.PathBase.Value, ctx.Request.Path.Value, SessionSlots.Current(ctx),
                ctx.Request.QueryString.Value!, SessionSlots.RootPathBase(ctx));
            return Task.CompletedTask;
        }).InvokeAsync(context);

        Assert.Equal(expectedBase, seen.Base);
        Assert.Equal(expectedPath, seen.Path);
        Assert.Equal(slot, seen.Slot);
        Assert.Equal("?q=1%2F2&x=%2Fs%2F2", seen.Query);
        Assert.Equal(pathBase, seen.Root.Value ?? "");
        // Restored for anything outside the pipeline (like UsePathBase does)
        Assert.Equal(pathBase, context.Request.PathBase.Value ?? "");
        Assert.Equal(path, context.Request.Path.Value);
    }

    [Theory]
    [InlineData("/s/0/Alerts")]
    [InlineData("/s/0")]
    [InlineData("/s/10/Alerts")]
    [InlineData("/s/10")]
    [InlineData("/s/a/Alerts")]
    [InlineData("/s2/x")]
    [InlineData("/S/2/Alerts")]   // case policy: only lower-case "/s/" (one canonical URL per slot)
    [InlineData("/s/2x/Alerts")]
    [InlineData("/s/")]
    [InlineData("/s")]
    [InlineData("/Alerts/s/2")]
    [InlineData("/")]
    public async Task Middleware_LeavesOtherPathsAlone(string path)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        (string? Base, string? Path, int Slot) seen = default;

        await new SessionSlotMiddleware(ctx =>
        {
            seen = (ctx.Request.PathBase.Value, ctx.Request.Path.Value, SessionSlots.Current(ctx));
            return Task.CompletedTask;
        }).InvokeAsync(context);

        Assert.True(string.IsNullOrEmpty(seen.Base));
        Assert.Equal(path, seen.Path);
        Assert.Equal(0, seen.Slot);
    }

    [Fact]
    public void Current_WithoutMiddleware_IsSlotZero()
    {
        Assert.Equal(0, SessionSlots.Current(new DefaultHttpContext()));
        Assert.Equal(0, SessionSlots.Current(null));
    }

    // ---------------------------------------------------------------- cookie names

    [Fact]
    public void CookieName_SlotZeroKeepsTheName()
    {
        Assert.Equal(AuthCookie, SessionSlots.CookieName(AuthCookie, 0));
        Assert.Equal(AuthCookie + ".s2", SessionSlots.CookieName(AuthCookie, 2));
        Assert.Equal(AuthCookie + ".s9", SessionSlots.CookieName(AuthCookie, 9));
    }

    private static DefaultHttpContext InSlot(int slot, string? cookieHeader = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        SessionSlots.Set(context, slot, PathString.Empty);
        context.Request.PathBase = slot == 0 ? PathString.Empty : new PathString("/s/" + slot);
        if (cookieHeader is not null)
            context.Request.Headers.Cookie = cookieHeader;
        return context;
    }

    private static string[] SetCookies(HttpContext context) => context.Response.Headers.SetCookie.ToArray()!;

    [Fact]
    public void CookieManager_ReadsTheCookieOfItsSlot()
    {
        var header = $"{AuthCookie}=zero; {AuthCookie}.s2=two; {AuthCookie}.s3=three";
        var manager = new SessionSlotCookieManager();

        Assert.Equal("zero", manager.GetRequestCookie(InSlot(0, header), AuthCookie));
        Assert.Equal("two", manager.GetRequestCookie(InSlot(2, header), AuthCookie));
        Assert.Equal("three", manager.GetRequestCookie(InSlot(3, header), AuthCookie));
        Assert.Null(manager.GetRequestCookie(InSlot(4, header), AuthCookie));
    }

    [Fact]
    public void CookieManager_WritesAndDeletesOnlyItsSlot()
    {
        var manager = new SessionSlotCookieManager();
        var options = new CookieOptions { Path = "/", HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict };

        var append = InSlot(2);
        manager.AppendResponseCookie(append, AuthCookie, "ticket", options);
        var set = Assert.Single(SetCookies(append));
        Assert.StartsWith($"{AuthCookie}.s2=ticket", set);
        Assert.Contains("path=/", set);

        var zero = InSlot(0);
        manager.AppendResponseCookie(zero, AuthCookie, "ticket", options);
        Assert.StartsWith($"{AuthCookie}=ticket", Assert.Single(SetCookies(zero)));

        var delete = InSlot(3, $"{AuthCookie}=zero; {AuthCookie}.s3=three");
        manager.DeleteCookie(delete, AuthCookie, options);
        var deleted = Assert.Single(SetCookies(delete));
        Assert.StartsWith($"{AuthCookie}.s3=;", deleted);
        Assert.Contains("expires=", deleted);
    }

    [Fact]
    public void CookieManager_ChunkedCookiesStayInTheSlot()
    {
        var manager = new SessionSlotCookieManager();
        var options = new CookieOptions { Path = "/", Secure = true };
        var big = new string('x', 9000);

        var append = InSlot(2);
        manager.AppendResponseCookie(append, AuthCookie, big, options);
        var names = SetCookies(append).Select(c => c[..c.IndexOf('=')]).ToList();
        Assert.True(names.Count >= 3);
        Assert.Equal($"{AuthCookie}.s2", names[0]);
        Assert.All(names.Skip(1), n => Assert.StartsWith($"{AuthCookie}.s2C", n));

        // Read back: the browser sends the chunks (and slot 0's cookie, which must not interfere)
        var header = string.Join("; ", SetCookies(append).Select(c => c[..c.IndexOf(';')])) + $"; {AuthCookie}=zero";
        Assert.Equal(big, manager.GetRequestCookie(InSlot(2, header), AuthCookie));
        Assert.Equal("zero", manager.GetRequestCookie(InSlot(0, header), AuthCookie));

        // Delete removes the slot's base cookie and all its chunks, nothing of slot 0
        var delete = InSlot(2, header);
        manager.DeleteCookie(delete, AuthCookie, options);
        var deleted = SetCookies(delete).Select(c => c[..c.IndexOf('=')]).ToList();
        Assert.Contains($"{AuthCookie}.s2", deleted);
        Assert.Contains($"{AuthCookie}.s2C1", deleted);
        Assert.DoesNotContain(AuthCookie, deleted);
    }

    // ---------------------------------------------------------------- free slots

    [Fact]
    public void FirstFreeSlot_IsTheLowestSlotWithoutSignInCookie()
    {
        Assert.Equal(1, SessionSlots.FirstFreeSlot([], AuthCookie));
        Assert.Equal(1, SessionSlots.FirstFreeSlot([AuthCookie, ".AspNetCore.Antiforgery.abc"], AuthCookie));
        Assert.Equal(2, SessionSlots.FirstFreeSlot([AuthCookie, AuthCookie + ".s1", AuthCookie + ".s3"], AuthCookie));
        // Chunk cookies alone do not count; the base cookie is always there when a slot is signed in
        Assert.Equal(1, SessionSlots.FirstFreeSlot([AuthCookie + ".s1C1"], AuthCookie));
        // Similar names of other cookies do not count
        Assert.Equal(1, SessionSlots.FirstFreeSlot([".AspNetCore.Mvc.CookieTempDataProvider.s1", AuthCookie + ".s10"], AuthCookie));

        var all = Enumerable.Range(1, 9).Select(s => AuthCookie + ".s" + s).ToList();
        Assert.Null(SessionSlots.FirstFreeSlot(all, AuthCookie));
        Assert.Equal(5, SessionSlots.FirstFreeSlot(all.Where(n => !n.EndsWith(".s5")), AuthCookie));
    }

    [Fact]
    public void UsedSlots_IncludesSlotZero()
    {
        Assert.Equal([0, 2, 7], SessionSlots.UsedSlots([AuthCookie + ".s7", "other", AuthCookie, AuthCookie + ".s2"], AuthCookie));
        Assert.Empty(SessionSlots.UsedSlots([], AuthCookie));
    }

    [Fact]
    public void PathBaseFor_BuildsTheOtherSlotsPrefix()
    {
        var context = InSlot(2);
        Assert.Equal("/s/4", SessionSlots.PathBaseFor(context, 4).Value);
        Assert.Equal("", SessionSlots.PathBaseFor(context, 0).Value ?? "");

        var hosted = new DefaultHttpContext();
        SessionSlots.Set(hosted, 2, new PathString("/app"));
        hosted.Request.PathBase = "/app/s/2";
        Assert.Equal("/app/s/5", SessionSlots.PathBaseFor(hosted, 5).Value);
        Assert.Equal("/app", SessionSlots.PathBaseFor(hosted, 0).Value);
        Assert.Throws<ArgumentOutOfRangeException>(() => SessionSlots.PathBaseFor(hosted, 10));
    }

    // ---------------------------------------------------------------- return URLs and links

    [Fact]
    public void CurrentUrl_IncludesPathBaseAndQuery()
    {
        var context = InSlot(3);
        context.Request.Path = "/ThreatIntel/Lookup";
        context.Request.QueryString = new QueryString("?q=1.2.3.4");
        Assert.Equal("/s/3/ThreatIntel/Lookup?q=1.2.3.4", SessionSlots.CurrentUrl(context.Request));
        Assert.Equal("/s/3/ThreatIntel/Lookup", SessionSlots.CurrentUrl(context.Request, includeQuery: false));

        var zero = InSlot(0);
        zero.Request.Path = "/Soc2";
        Assert.Equal("/Soc2", SessionSlots.CurrentUrl(zero.Request));
    }

    [Theory]
    [InlineData(2, "/s/2/Alerts/Details/5", true)]
    [InlineData(2, "/s/2", true)]
    [InlineData(2, "/s/2?tab=mine", true)]
    [InlineData(2, "/s/2/Soc2?tab=mine#x", true)]
    [InlineData(2, "/Alerts", false)]          // slot 0 page: another user may be signed in there
    [InlineData(2, "/s/3/Alerts", false)]      // another slot
    [InlineData(2, "/s/23/Alerts", false)]
    [InlineData(0, "/Alerts/Details/5", true)]
    [InlineData(0, "/", true)]
    [InlineData(0, "/s/2/Alerts", false)]
    [InlineData(0, "/s/2", false)]
    [InlineData(0, "/s/0/Alerts", true)]       // not a slot path (404, but harmless)
    [InlineData(0, "//evil.example/x", false)]
    [InlineData(0, "/\\evil.example/x", false)]
    [InlineData(0, "https://evil.example/", false)]
    [InlineData(2, "//evil.example/s/2", false)]
    [InlineData(0, "", false)]
    [InlineData(0, null, false)]
    [InlineData(0, "Alerts", false)]
    public void IsLocalToCurrentSlot_KeepsTheUserInTheirSession(int slot, string? url, bool expected) =>
        Assert.Equal(expected, SessionSlots.IsLocalToCurrentSlot(InSlot(slot).Request, url));

    [Theory]
    [InlineData("/s/2", "/Alerts/Details/5", "/s/2/Alerts/Details/5")]
    [InlineData("", "/Alerts/Details/5", "/Alerts/Details/5")]
    [InlineData("/s/2", "/Alerts/Details/5#comments", "/s/2/Alerts/Details/5#comments")]
    [InlineData("/s/2", "//evil.example/x", null)]
    [InlineData("/s/2", "/\\evil.example/x", null)]
    [InlineData("/s/2", "https://evil.example/x", null)]
    [InlineData("/s/2", "javascript:alert(1)", null)]
    [InlineData("/s/2", "Alerts/Details/5", null)]
    [InlineData("/s/2", "/Alerts/\nDetails", null)]
    [InlineData("/s/2", null, null)]
    [InlineData("/s/2", "", null)]
    public void AppLink_PrefixesTheSessionAndRejectsForeignLinks(string pathBase, string? link, string? expected) =>
        Assert.Equal(expected, SessionSlots.AppLink(new PathString(pathBase.Length == 0 ? null : pathBase), link));

    [Fact]
    public void NotificationLinks_FromTheServiceAreLocalPaths() =>
        Assert.Equal("/s/4/Alerts/Details/12", SessionSlots.AppLink("/s/4", NotificationService.AlertLink(12)));

    // ---------------------------------------------------------------- real pipeline: cookie handler, links, antiforgery

    private sealed class Pipeline
    {
        public required RequestDelegate App { get; init; }
        public required IServiceProvider Services { get; init; }

        /// <summary>Simulates one request of a browser that holds <paramref name="jar"/>.</summary>
        public async Task<HttpContext> SendAsync(string method, string pathAndQuery, Dictionary<string, string> jar,
            Action<HttpContext>? prepare = null)
        {
            var context = new DefaultHttpContext { RequestServices = Services.CreateScope().ServiceProvider };
            context.Request.Method = method;
            context.Request.Scheme = "https";
            context.Request.Host = new HostString("localhost");
            var q = pathAndQuery.IndexOf('?');
            context.Request.Path = q < 0 ? pathAndQuery : pathAndQuery[..q];
            if (q >= 0)
                context.Request.QueryString = new QueryString(pathAndQuery[q..]);
            if (jar.Count > 0)
                context.Request.Headers.Cookie = string.Join("; ", jar.Select(c => $"{c.Key}={c.Value}"));
            context.Response.Body = new MemoryStream();
            prepare?.Invoke(context);
            await App(context);

            // Browser behaviour: store / delete the cookies of the response (all have path "/")
            foreach (var header in context.Response.Headers.SetCookie)
            {
                var parsed = Microsoft.Net.Http.Headers.SetCookieHeaderValue.Parse(header);
                Assert.Equal("/", parsed.Path.Value);
                if (parsed.Expires is { } expires && expires < DateTimeOffset.UtcNow)
                    jar.Remove(parsed.Name.Value!);
                else
                    jar[parsed.Name.Value!] = parsed.Value.Value!;
            }
            return context;
        }

        public static string Body(HttpContext context)
        {
            context.Response.Body.Position = 0;
            return new StreamReader(context.Response.Body).ReadToEnd();
        }
    }

    private static Pipeline BuildPipeline()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddRouting();
        services.AddSingleton(new DiagnosticListener("tests"));
        services.AddSingleton<DiagnosticSource>(sp => sp.GetRequiredService<DiagnosticListener>());
        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options =>
            {
                // Same settings as Program.cs (ConfigureApplicationCookie + session slots)
                options.LoginPath = "/Account/Login";
                options.Cookie.Name = AuthCookie;
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Strict;
                options.CookieManager = new SessionSlotCookieManager();
                options.Cookie.Path = "/";
            });
        services.AddAntiforgery(options => options.Cookie.Path = "/");
        services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
        var provider = services.BuildServiceProvider();

        var app = new ApplicationBuilder(provider);
        app.UseMiddleware<SessionSlotMiddleware>();
        app.UseRouting();
        app.UseAuthentication();
        app.UseEndpoints(e =>
        {
            e.MapGet("/signin/{name}", (HttpContext ctx, string name) => ctx.SignInAsync(new ClaimsPrincipal(
                new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "id-" + name), new Claim(ClaimTypes.Name, name)],
                    CookieAuthenticationDefaults.AuthenticationScheme))));
            e.MapGet("/signout", (HttpContext ctx) => ctx.SignOutAsync());
            e.MapGet("/whoami", (HttpContext ctx) => ctx.Response.WriteAsync(ctx.User.Identity?.Name ?? "anonymous"));
            e.MapGet("/secret", (HttpContext ctx) => ctx.User.Identity?.IsAuthenticated == true
                ? ctx.Response.WriteAsync("secret")
                : ctx.ChallengeAsync());
            e.MapGet("/Alerts/Details/{id}", () => "details").WithName("alert-details");
            e.MapGet("/link", (HttpContext ctx, LinkGenerator links) =>
                ctx.Response.WriteAsync(links.GetPathByName(ctx, "alert-details", new { id = 5 })!));
            e.MapGet("/form", (HttpContext ctx, IAntiforgery antiforgery) =>
                ctx.Response.WriteAsync(antiforgery.GetAndStoreTokens(ctx).RequestToken!));
            e.MapPost("/post", async (HttpContext ctx, IAntiforgery antiforgery) =>
                await antiforgery.IsRequestValidAsync(ctx) ? Results.Text("ok:" + ctx.User.Identity?.Name) : Results.BadRequest());
        });
        return new Pipeline { App = app.Build(), Services = provider };
    }

    [Fact]
    public async Task Pipeline_EachSlotHasItsOwnUser()
    {
        var pipeline = BuildPipeline();
        var jar = new Dictionary<string, string>();

        await pipeline.SendAsync("GET", "/signin/alice", jar);
        await pipeline.SendAsync("GET", "/s/2/signin/bob", jar);
        await pipeline.SendAsync("GET", "/s/5/signin/carol", jar);

        Assert.Contains(AuthCookie, jar.Keys);
        Assert.Contains(AuthCookie + ".s2", jar.Keys);
        Assert.Contains(AuthCookie + ".s5", jar.Keys);
        Assert.Equal("alice", Pipeline.Body(await pipeline.SendAsync("GET", "/whoami", jar)));
        Assert.Equal("bob", Pipeline.Body(await pipeline.SendAsync("GET", "/s/2/whoami", jar)));
        Assert.Equal("carol", Pipeline.Body(await pipeline.SendAsync("GET", "/s/5/whoami", jar)));
        Assert.Equal("anonymous", Pipeline.Body(await pipeline.SendAsync("GET", "/s/3/whoami", jar)));
        Assert.Equal(1, SessionSlots.FirstFreeSlot(jar.Keys, AuthCookie));

        // Sign-out in slot 2 removes only bob's cookie
        var signOut = await pipeline.SendAsync("GET", "/s/2/signout", jar);
        Assert.All(signOut.Response.Headers.SetCookie, c => Assert.StartsWith(AuthCookie + ".s2=", c));
        Assert.Equal("anonymous", Pipeline.Body(await pipeline.SendAsync("GET", "/s/2/whoami", jar)));
        Assert.Equal("alice", Pipeline.Body(await pipeline.SendAsync("GET", "/whoami", jar)));
        Assert.Equal("carol", Pipeline.Body(await pipeline.SendAsync("GET", "/s/5/whoami", jar)));
    }

    [Fact]
    public async Task Pipeline_LoginRedirectKeepsTheSlot()
    {
        var pipeline = BuildPipeline();
        var response = (await pipeline.SendAsync("GET", "/s/3/secret?x=1", [])).Response;

        Assert.Equal(StatusCodes.Status302Found, response.StatusCode);
        Assert.Equal("https://localhost/s/3/Account/Login?ReturnUrl=%2Fs%2F3%2Fsecret%3Fx%3D1", response.Headers.Location.ToString());

        var zero = (await pipeline.SendAsync("GET", "/secret", [])).Response;
        Assert.Equal("https://localhost/Account/Login?ReturnUrl=%2Fsecret", zero.Headers.Location.ToString());
    }

    [Fact]
    public async Task Pipeline_GeneratedLinksCarryTheSlot()
    {
        var pipeline = BuildPipeline();
        Assert.Equal("/s/3/Alerts/Details/5", Pipeline.Body(await pipeline.SendAsync("GET", "/s/3/link", [])));
        Assert.Equal("/Alerts/Details/5", Pipeline.Body(await pipeline.SendAsync("GET", "/link", [])));
    }

    [Fact]
    public async Task Pipeline_AntiforgeryTokenIsBoundToTheSlotsUser()
    {
        var pipeline = BuildPipeline();
        var jar = new Dictionary<string, string>();
        await pipeline.SendAsync("GET", "/signin/alice", jar);
        await pipeline.SendAsync("GET", "/s/2/signin/bob", jar);

        // Form rendered in slot 2 (bob); the antiforgery cookie has path "/" (checked in SendAsync) and is shared
        var token = Pipeline.Body(await pipeline.SendAsync("GET", "/s/2/form", jar));
        Assert.Single(jar.Keys, k => k.StartsWith(".AspNetCore.Antiforgery.", StringComparison.Ordinal));
        void WithToken(HttpContext ctx) => ctx.Request.Headers["RequestVerificationToken"] = token;

        // Posted in slot 2 → validated against bob
        Assert.Equal("ok:bob", Pipeline.Body(await pipeline.SendAsync("POST", "/s/2/post", jar, WithToken)));
        // The same token posted in slot 0 (alice) or an empty slot is rejected
        Assert.Equal(StatusCodes.Status400BadRequest, (await pipeline.SendAsync("POST", "/post", jar, WithToken)).Response.StatusCode);
        Assert.Equal(StatusCodes.Status400BadRequest, (await pipeline.SendAsync("POST", "/s/4/post", jar, WithToken)).Response.StatusCode);

        // A form of slot 0 still works after slot 2 created its token (one shared antiforgery cookie)
        var aliceToken = Pipeline.Body(await pipeline.SendAsync("GET", "/form", jar));
        Assert.Equal("ok:alice", Pipeline.Body(await pipeline.SendAsync("POST", "/post", jar,
            ctx => ctx.Request.Headers["RequestVerificationToken"] = aliceToken)));
    }

    // ---------------------------------------------------------------- TempData

    [Fact]
    public void TempData_IsKeptPerSlot()
    {
        var mvc = new ServiceCollection();
        mvc.AddLogging();
        mvc.AddControllersWithViews();
        var serializer = mvc.BuildServiceProvider().GetRequiredService<TempDataSerializer>();
        var provider = new SessionSlotTempDataProvider(new EphemeralDataProtectionProvider(), NullLoggerFactory.Instance,
            Options.Create(new CookieTempDataProviderOptions()), serializer);

        var save = InSlot(2);
        provider.SaveTempData(save, new Dictionary<string, object> { ["Success"] = "Alert escalated to SOC 2." });
        var cookie = Assert.Single(SetCookies(save));
        Assert.StartsWith(".AspNetCore.Mvc.CookieTempDataProvider.s2=", cookie);
        Assert.Contains("path=/;", cookie + ";");
        var header = cookie[..cookie.IndexOf(';')];

        Assert.Equal("Alert escalated to SOC 2.", provider.LoadTempData(InSlot(2, header))["Success"]);
        Assert.Empty(provider.LoadTempData(InSlot(0, header)));
        Assert.Empty(provider.LoadTempData(InSlot(3, header)));
    }
}
