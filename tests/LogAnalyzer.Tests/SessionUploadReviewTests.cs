using System.Diagnostics;
using System.IO.Compression;
using System.Security.Claims;
using System.Text;
using LogAnalyzer.Web.Controllers;
using LogAnalyzer.Web.Helpers;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.Services.LogFormats;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace LogAnalyzer.Tests;

/// <summary>Bugs found in the review of the session slots and the upload / worker integration (2026-11-25).</summary>
public class SessionUploadReviewTests
{
    private const string AuthCookie = ".AspNetCore.Identity.Application";

    private static HttpRequest InSlot(int slot, string root = "")
    {
        var context = new DefaultHttpContext();
        SessionSlots.Set(context, slot, new PathString(root));
        context.Request.PathBase = new PathString(root + (slot == 0 ? "" : "/s/" + slot));
        return context.Request;
    }

    // ---------------------------------------------------------------- return URLs

    // The browser resolves dot segments ("%2e" too) and turns "\" into "/" after the check; the server decodes %73.
    [Theory]
    [InlineData(2, "/s/2/../Alerts")]
    [InlineData(2, "/s/2/../../s/3/Alerts")]
    [InlineData(2, "/s/2/../3/Alerts")]
    [InlineData(2, "/s/2/%2e%2e/3/Alerts")]
    [InlineData(2, "/s/2/.%2E/3/Alerts")]
    [InlineData(2, "/s/2/..\\3/Alerts")]
    [InlineData(2, "/s/2/x/../../3")]
    [InlineData(2, "/s/2/..")]
    [InlineData(2, "/s/2\\..\\3")]
    [InlineData(2, "/s/2/%2e%2e%2f3")]
    [InlineData(2, "/S/2/Alerts")]            // another case is not a slot path: it would land in slot 0
    [InlineData(2, "/s/%33/Alerts")]
    [InlineData(0, "/x/../s/2/Alerts")]
    [InlineData(0, "/./s/2")]
    [InlineData(0, "/%73/2/Alerts")]
    [InlineData(0, "/s/%32/Alerts")]
    [InlineData(0, "/s\\2/Alerts")]
    [InlineData(0, "/.//evil.example/")]
    [InlineData(0, "/%5cevil.example/")]
    [InlineData(0, "/%2fevil.example/")]
    [InlineData(0, "/%09/evil.example/")]
    public void ReturnUrl_CannotLeaveTheSlotThroughNormalisation(int slot, string url) =>
        Assert.False(SessionSlots.IsLocalToCurrentSlot(InSlot(slot), url));

    // A Location header must be ASCII: Kestrel answered 500 after a successful sign-in.
    [Theory]
    [InlineData(0, "/Alerts?ip=é")]
    [InlineData(3, "/s/3/Alerts?ip=é")]
    [InlineData(0, "/Alerts x")]
    public void ReturnUrl_MustBeAValidHeaderValue(int slot, string url) =>
        Assert.False(SessionSlots.IsLocalToCurrentSlot(InSlot(slot), url));

    [Theory]
    [InlineData(2, "/s/2/ThreatIntel/Lookup?q=https%3A%2F%2Fx.com%2F..%2Fy")]
    [InlineData(2, "/s/2/ThreatIntel/Lookup?q=../x&back=/s/3")]
    [InlineData(0, "/Alerts?ip=2001%3Adb8%3A%3A5#e..x")]
    [InlineData(0, "/LogFiles/Details/5...")]
    [InlineData(0, "/LogFiles/caf%C3%A9")]
    public void ReturnUrl_NormalPagesStillWork(int slot, string url) =>
        Assert.True(SessionSlots.IsLocalToCurrentSlot(InSlot(slot), url));

    [Fact]
    public void ReturnUrl_EscapedPathBaseMatches()
    {
        var request = InSlot(2, "/my app");
        request.Path = "/Alerts";
        var url = SessionSlots.CurrentUrl(request);
        Assert.Equal("/my%20app/s/2/Alerts", url);
        Assert.True(SessionSlots.IsLocalToCurrentSlot(request, url));
    }

    // ---------------------------------------------------------------- pipeline: expired sessions, errors

    private static (RequestDelegate App, IServiceProvider Services) BuildPipeline()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddRouting();
        services.AddSingleton(new DiagnosticListener("tests"));
        services.AddSingleton<DiagnosticSource>(sp => sp.GetRequiredService<DiagnosticListener>());
        services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options =>
            {
                options.LoginPath = "/Account/Login";
                options.AccessDeniedPath = "/Account/AccessDenied";
                options.Cookie.Name = AuthCookie;
                options.CookieManager = new SessionSlotCookieManager();
                options.Cookie.Path = "/";
                SessionCookieEvents.Configure(options);   // as in Program.cs
            });
        var provider = services.BuildServiceProvider();
        var app = new ApplicationBuilder(provider);
        app.UseMiddleware<SessionSlotMiddleware>();
        app.UseExceptionHandler("/Home/Error");
        app.UseRouting();
        app.UseAuthentication();
        app.UseEndpoints(e =>
        {
            e.Map("/secret", ctx => ctx.ChallengeAsync());
            e.Map("/forbidden", ctx => ctx.ForbidAsync());
            e.Map("/boom", (HttpContext _) => throw new InvalidOperationException("boom"));
            e.Map("/Home/Error", ctx => ctx.Response.WriteAsync(
                $"{ctx.Request.PathBase}|{ctx.Request.Path}|{SessionSlots.Current(ctx)}"));
        });
        return (app.Build(), provider);
    }

    private static async Task<HttpContext> SendAsync(string method, string path, string? accept = null)
    {
        var (app, services) = BuildPipeline();
        var context = new DefaultHttpContext { RequestServices = services.CreateScope().ServiceProvider };
        context.Request.Method = method;
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        context.Request.Path = path;
        if (accept is not null)
            context.Request.Headers.Accept = accept;
        context.Response.Body = new MemoryStream();
        await app(context);
        return context;
    }

    private const string BrowserAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

    [Theory]
    [InlineData("GET", "/secret")]
    [InlineData("POST", "/s/2/secret")]
    public async Task ExpiredSession_BackgroundRequestsGet401_NotTheSignInPage(string method, string path)
    {
        var response = (await SendAsync(method, path, "application/json")).Response;
        Assert.Equal(StatusCodes.Status401Unauthorized, response.StatusCode);
        Assert.Equal("", response.Headers.Location.ToString());
    }

    [Fact]
    public async Task ExpiredSession_PagesGoToTheSignInPageOfTheirSlot()
    {
        var get = (await SendAsync("GET", "/s/2/secret", BrowserAccept)).Response;
        Assert.Equal("https://localhost/s/2/Account/Login?ReturnUrl=%2Fs%2F2%2Fsecret", get.Headers.Location.ToString());

        // A form address cannot be opened after signing in (405): no return URL.
        var post = (await SendAsync("POST", "/s/2/secret", BrowserAccept)).Response;
        Assert.Equal(StatusCodes.Status302Found, post.StatusCode);
        Assert.Equal("https://localhost/s/2/Account/Login", post.Headers.Location.ToString());
    }

    [Fact]
    public async Task AccessDenied_StaysInTheSlot()
    {
        var page = (await SendAsync("GET", "/s/4/forbidden", BrowserAccept)).Response;
        Assert.StartsWith("https://localhost/s/4/Account/AccessDenied", page.Headers.Location.ToString());
        var json = (await SendAsync("GET", "/s/4/forbidden", "application/json")).Response;
        Assert.Equal(StatusCodes.Status403Forbidden, json.StatusCode);
    }

    [Fact]
    public async Task ErrorPage_IsReExecutedInTheSlotAndThePathIsRestored()
    {
        var context = await SendAsync("GET", "/s/2/boom", BrowserAccept);
        context.Response.Body.Position = 0;
        Assert.Equal("/s/2|/Home/Error|2", await new StreamReader(context.Response.Body).ReadToEndAsync());
        Assert.Equal(StatusCodes.Status500InternalServerError, context.Response.StatusCode);
        Assert.Equal("", context.Request.PathBase.Value ?? "");
        Assert.Equal("/s/2/boom", context.Request.Path.Value);
    }

    // ---------------------------------------------------------------- "Sign in another account"

    private sealed class CookieOptionsMonitor : IOptionsMonitor<CookieAuthenticationOptions>
    {
        private readonly CookieAuthenticationOptions options = new() { Cookie = { Name = AuthCookie } };
        public CookieAuthenticationOptions CurrentValue => options;
        public CookieAuthenticationOptions Get(string? name) => options;
        public IDisposable? OnChange(Action<CookieAuthenticationOptions, string?> listener) => null;
    }

    private static AccountController Account(int slot, string cookies, string? user = null)
    {
        var http = InSlot(slot).HttpContext;
        http.Request.Headers.Cookie = cookies;
        if (user is not null)
            http.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, user)], "test"));
        var controller = new AccountController(null!, null!, null!, new CookieOptionsMonitor(), null!)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
            Url = new UrlHelper(new ActionContext(http, new RouteData(), new ActionDescriptor())),
            TempData = new TempDataDictionary(http, new NoTempData())
        };
        return controller;
    }

    private sealed class NoTempData : ITempDataProvider
    {
        public IDictionary<string, object> LoadTempData(HttpContext context) => new Dictionary<string, object>();
        public void SaveTempData(HttpContext context, IDictionary<string, object> values) { }
    }

    [Theory]
    [InlineData(0, AuthCookie + "=a", "/s/1/Account/Login")]
    [InlineData(0, AuthCookie + "=a; " + AuthCookie + ".s1=b", "/s/2/Account/Login")]   // an old tab: slot 1 is in use by now
    [InlineData(3, AuthCookie + ".s1=b; " + AuthCookie + ".s3=c", "/s/2/Account/Login")]
    public void NewSession_ChoosesTheFreeSlotAtTheClick(int slot, string cookies, string expected) =>
        Assert.Equal(expected, Assert.IsType<LocalRedirectResult>(Account(slot, cookies, "alice").NewSession()).Url);

    [Fact]
    public void NewSession_AllSlotsInUse_SaysSo()
    {
        var controller = Account(0, string.Join("; ", Enumerable.Range(1, 9).Select(s => $"{AuthCookie}.s{s}=x")), "alice");
        var redirect = Assert.IsType<RedirectToActionResult>(controller.NewSession());
        Assert.Equal(("Home", "Index"), (redirect.ControllerName, redirect.ActionName));
        Assert.Contains("in use", (string)controller.TempData["Error"]!);
    }

    // The sign-in form of an occupied slot replaced its account: bob's tab turned into carol's.
    [Theory]
    [InlineData(1, null, "/s/1/")]
    [InlineData(1, "/s/1/Alerts", "/s/1/Alerts")]
    [InlineData(1, "/s/2/Alerts", "/s/1/")]
    [InlineData(0, "//evil.example", "/")]
    public async Task Login_InASignedInSession_ShowsNoFormButTheSession(int slot, string? returnUrl, string expected)
    {
        var result = await Account(slot, $"{SessionSlots.CookieName(AuthCookie, slot)}=x", "bob").Login(returnUrl);
        Assert.Equal(expected, Assert.IsType<LocalRedirectResult>(result).Url);
    }

    // Two tabs with the sign-in form of one slot: the second one was answered with an empty "400" page.
    [Theory]
    [InlineData("bob", "already belongs")]
    [InlineData(null, "outdated")]
    public void Login_WithAnOutdatedForm_GoesBackToTheSignInPage(string? user, string message)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddControllersWithViews();
        services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
        services.Replace(ServiceDescriptor.Singleton<ITempDataProvider, SessionSlotTempDataProvider>());
        var provider = services.BuildServiceProvider();

        var http = InSlot(1).HttpContext;
        http.RequestServices = provider;
        if (user is not null)
            http.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, user)], "test"));
        var action = new ActionContext(http, new RouteData(), new ActionDescriptor());

        var context = new ResultExecutingContext(action, [], new AntiforgeryValidationFailedResult(), new object());
        new ReloadOutdatedSignInFormAttribute().OnResultExecuting(context);

        var redirect = Assert.IsType<RedirectToActionResult>(context.Result);
        Assert.Equal(("Account", "Login"), (redirect.ControllerName, redirect.ActionName));
        var cookie = Assert.Single(http.Response.Headers.SetCookie.ToArray())!;
        Assert.StartsWith(".AspNetCore.Mvc.CookieTempDataProvider.s1=", cookie);

        var next = InSlot(1).HttpContext;
        next.RequestServices = provider;
        next.Request.Headers.Cookie = cookie[..cookie.IndexOf(';')];
        Assert.Contains(message, (string)provider.GetRequiredService<ITempDataDictionaryFactory>().GetTempData(next)["Error"]!);

        // Any other result (wrong password page, redirect after sign-in) is left alone
        var ok = new ResultExecutingContext(action, [], new ViewResult(), new object());
        new ReloadOutdatedSignInFormAttribute().OnResultExecuting(ok);
        Assert.IsType<ViewResult>(ok.Result);
    }

    // ---------------------------------------------------------------- import: format detection

    private static readonly LogParseContext Ctx = new(new DateTimeOffset(2026, 11, 21, 12, 0, 0, TimeSpan.Zero), TimeSpan.Zero);

    private const string Forti = "date=2026-11-21 time=10:00:00 devname=\"fw01\" logid=\"0000000013\" type=\"traffic\" " +
                                 "subtype=\"forward\" srcip=203.0.113.5 srcport=4000 dstip=10.0.0.5 dstport=22 proto=6 action=\"deny\"";

    private static async Task<string?> DetectAsync(string text) =>
        (await LogImport.DetectAsync(new BoundedLineReader(new StringReader(text), 16 * 1024), Ctx, CancellationToken.None)).Format?.Id;

    private static string Lines(int count, string line) => string.Concat(Enumerable.Repeat(line + "\n", count));

    [Fact]
    public async Task Detection_LooksBehindALongPreamble()
    {
        Assert.Equal("fortigate", await DetectAsync(Lines(50, Forti)));
        Assert.Equal("fortigate", await DetectAsync(Lines(250, "# exported by the log collector") + Lines(50, Forti)));
        Assert.Equal("fortigate", await DetectAsync(Lines(700, "INFO application started ok") + Lines(300, Forti)));
        Assert.Equal("fortigate", await DetectAsync(new string('x', 100_000) + "\n\n\n" + Lines(5, Forti)));
        Assert.Null(await DetectAsync(Lines(LogImport.MaxSampleLines + 1000, "INFO application started ok") + Lines(300, Forti)));
    }

    [Fact]
    public async Task Detection_KeepsColumnHeadersForLaterBlocks()
    {
        // Columns in an order only the "#Fields" line explains, more than 200 comment lines before the first event.
        var text = "#Fields: date time action protocol dst-ip src-ip dst-port src-port\n"
                   + Lines(300, "# comment")
                   + Lines(20, "2026-11-21 10:00:00 DROP TCP 10.0.0.5 203.0.113.5 22 51000");
        Assert.Equal("windows-firewall", await DetectAsync(text));
    }

    [Theory]
    [InlineData("")]
    [InlineData("\n\n  \n")]
    [InlineData("INFO application started ok\n")]
    public async Task Detection_FindsNothingInOtherText(string text) => Assert.Null(await DetectAsync(text));

    [Fact]
    public async Task Detection_ReadsGzipAndStopsAtTheDecompressedLimit()
    {
        static MemoryStream Gzip(string text)
        {
            var ms = new MemoryStream();
            using (var gz = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
                gz.Write(Encoding.UTF8.GetBytes(text));
            ms.Position = 0;
            return ms;
        }
        static BoundedLineReader Reader(Stream s, long cap) => new(new StreamReader(new LimitedReadStream(
            new GZipStream(s, CompressionMode.Decompress), cap, "too big")), 16 * 1024);

        var ok = await LogImport.DetectAsync(Reader(Gzip(Lines(50, Forti)), 1_000_000), Ctx, CancellationToken.None);
        Assert.Equal("fortigate", ok.Format?.Id);
        await Assert.ThrowsAsync<LogLimitExceededException>(() => LogImport.DetectAsync(
            Reader(Gzip(new string('x', 5_000_000)), 1_000_000), Ctx, CancellationToken.None));
    }

    // ---------------------------------------------------------------- import: clear results

    [Fact]
    public void UnreadableFile_IsFailedWithAnExplanation()
    {
        var auto = LogImport.FailureMessage(300, 0, requested: null);
        Assert.Contains("not recognised", auto);
        Assert.Contains("choose its log format", auto);

        var forti = LogFormatRegistry.Find("fortigate")!;
        var web = LogFormatRegistry.Find("combined")!;
        var wrong = LogImport.FailureMessage(2933, 0, forti, web);
        Assert.Contains(forti.DisplayName, wrong);
        Assert.Contains("looks like: " + web.DisplayName, wrong);
        Assert.DoesNotContain("looks like", LogImport.FailureMessage(10, 0, forti, forti));
        Assert.DoesNotContain("looks like", LogImport.FailureMessage(10, 0, forti));

        Assert.Null(LogImport.FailureMessage(300, 1, null));     // something was read
        Assert.Null(LogImport.FailureMessage(0, 0, forti));      // headers only: nothing to read
        Assert.All([auto, wrong], m => Assert.True(m!.Length <= 2000));
    }

    private static LogFile Imported(int total, int parsed, LogSource source = LogSource.WebAccess, string? format = null,
        LogFileStatus status = LogFileStatus.Completed) =>
        new() { TotalLines = total, ParsedLines = parsed, FailedLines = total - parsed, Source = source, Format = format, Status = status };

    [Fact]
    public void FilesImportedBeforeFormatsWereStored_AreAccessLogs()
    {
        var old = Imported(2933, 2930);
        Assert.Equal("Apache / Nginx access log", LogImport.FormatLabel(old));
        Assert.False(LogImport.NotRecognised(old));
        Assert.Null(LogImport.Notice(old));
    }

    [Fact]
    public void NotRecognised_OnlyWhenNothingWasRead()
    {
        Assert.True(LogImport.NotRecognised(Imported(300, 0)));
        Assert.True(LogImport.NotRecognised(Imported(300, 0, status: LogFileStatus.Failed)));
        Assert.False(LogImport.NotRecognised(Imported(0, 0, status: LogFileStatus.Failed)));      // e.g. a broken gzip file
        Assert.False(LogImport.NotRecognised(Imported(300, 0, status: LogFileStatus.Processing)));
        Assert.False(LogImport.NotRecognised(Imported(65, 65, LogSource.Firewall, "Fortinet FortiGate")));
        Assert.Null(LogImport.FormatLabel(Imported(300, 0)));
    }

    [Fact]
    public void Notice_ExplainsEmptyAndMostlyUnreadableFiles()
    {
        Assert.Contains("no events", LogImport.Notice(Imported(0, 0, LogSource.Firewall, "Windows Defender Firewall")));
        Assert.Contains("could be read", LogImport.Notice(Imported(300, 0)));
        Assert.Contains("Only 30 of 100 lines", LogImport.Notice(Imported(100, 30)));
        Assert.Null(LogImport.Notice(Imported(100, 60)));
        Assert.Null(LogImport.Notice(Imported(0, 0, status: LogFileStatus.Pending)));
        Assert.Null(LogImport.Notice(Imported(300, 0, status: LogFileStatus.Failed)));   // has its ErrorMessage
    }

    // TotalLines leaves out header / skipped lines: labels of the last lines were dropped silently.
    [Fact]
    public void Labels_OfLinesBehindSkippedLinesAreKept()
    {
        var file = new LogFile { TotalLines = 51, ParsedLines = 51 };   // samples/firewall/windows-firewall.log: 5 other lines
        var labels = EvaluationService.ParseLabels(new MemoryStream("5,normal\n55,portscan\n56,c2\n"u8.ToArray()),
            LogImport.MaxLabelLine(file, lastEventLine: 56));
        Assert.Equal([5, 55, 56], labels.Keys.Order());

        Assert.Equal(1, LogImport.MaxLabelLine(new LogFile(), 0));
        Assert.Equal(2936, LogImport.MaxLabelLine(new LogFile { TotalLines = 2933, FailedLines = 3 }, 2933));
        Assert.Equal(int.MaxValue, LogImport.MaxLabelLine(new LogFile { TotalLines = int.MaxValue, FailedLines = 5 }, 1));
    }

    [Fact]
    public void Cut_KeepsSurrogatePairsWhole()
    {
        var smile = char.ConvertFromUtf32(0x1F600);
        Assert.Equal("a", LogImport.Cut("a" + smile, 2));
        Assert.Equal("a" + smile, LogImport.Cut("a" + smile + "b", 3));
        Assert.Equal("ab", LogImport.Cut("abc", 2));
        Assert.Equal("ab", LogImport.Cut("ab", 2));
        Assert.Equal("", LogImport.Cut(smile, 1));
        Assert.Null(LogImport.Cut(null, 5));
    }

    // ---------------------------------------------------------------- report and display helpers

    [Fact]
    public void EvidenceLine_ShowsTheMessageOfEventsWithoutDestination()
    {
        var login = new LogEvent
        {
            LineNumber = 7, Timestamp = new DateTimeOffset(2026, 11, 21, 10, 0, 0, TimeSpan.Zero), ClientIp = "203.0.113.9",
            Method = "DENY", Action = FirewallAction.Deny, EventType = "auth", Url = "Login failed for user admin"
        };
        Assert.StartsWith("line 7  ", ReportService.EvidenceLine(login));
        Assert.EndsWith("10:00:00  DENY 203.0.113.9  Login failed for user admin", ReportService.EvidenceLine(login));

        login.DestinationIp = "10.0.0.5";
        login.DestinationPort = 22;
        login.Transport = "tcp";
        login.RuleName = "block-ssh";
        Assert.EndsWith("DENY tcp 203.0.113.9 -> 10.0.0.5:22  [block-ssh]", ReportService.EvidenceLine(login));
    }

    [Fact]
    public void EvidenceLine_IsOneShortLineWithoutControlCharacters()
    {
        var smile = char.ConvertFromUtf32(0x1F600);
        var line = ReportService.EvidenceLine(new LogEvent
        {
            ClientIp = "-", Method = "EVENT", Action = FirewallAction.Unknown,
            Url = "a\r\nline 1  forged\u001b[31m\0" + string.Concat(Enumerable.Repeat(smile, 300))
        });
        Assert.DoesNotContain(line, char.IsControl);
        Assert.True(line.Length < 230);
        Assert.False(char.IsHighSurrogate(line[^4]), "a surrogate pair was cut in half before the dots");

        var web = ReportService.EvidenceLine(new LogEvent { ClientIp = "203.0.113.9", Method = "GET", Url = "/?q=%0d%0ax", StatusCode = 200 });
        Assert.DoesNotContain(web, char.IsControl);
    }

    [Theory]
    [InlineData(0, "00:00:00")]
    [InlineData(3723, "01:02:03")]
    [InlineData(108_000, "1 d 06:00:00")]   // was shown as 06:00:00
    public void Duration_ShowsDays(int seconds, string expected) =>
        Assert.Equal(expected, Format.Duration(TimeSpan.FromSeconds(seconds)));
}
