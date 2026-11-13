using System.Globalization;
using System.Text;

namespace LogAnalyzer.Tools;

/// <summary>
/// Generates a synthetic but realistic Combined-format access log with per-line ground truth.
/// Traffic is produced by independent "actors" (browsing sessions, crawlers, a monitor, attack campaigns)
/// scheduled on a common clock, so attacks are interleaved with normal traffic as in a real server log.
/// The generator deliberately includes cases the default rules miss (spoofed user agents, evasive payloads,
/// slow brute force) and benign look-alikes (crawlers, odd search terms) so the evaluation is not trivially 100%.
/// </summary>
public static class Generator
{
    public static int Run(Args a)
    {
        var lines = a.Int("lines", 100_000);
        var output = a.Required("out");
        var labels = a.Optional("labels") ?? Path.ChangeExtension(output, null) + ".labels.csv";
        var ratio = a.Double("attack-ratio", 0.02);
        var seed = a.Int("seed", 42);
        if (lines < 100) throw new ArgumentException("--lines must be at least 100.");
        if (ratio is < 0 or > 0.5) throw new ArgumentException("--attack-ratio must be between 0 and 0.5.");

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var stats = new SyntheticLog(seed, ratio).Write(output, labels, lines);
        sw.Stop();

        Console.WriteLine($"Wrote {lines:N0} lines to {output} ({new FileInfo(output).Length / 1024.0 / 1024.0:0.0} MB) in {sw.Elapsed.TotalSeconds:0.0} s");
        Console.WriteLine($"Labels: {labels}");
        foreach (var (label, count) in stats.OrderByDescending(s => s.Value))
            Console.WriteLine($"  {label,-12} {count,10:N0}  ({100.0 * count / lines:0.00}%)");
        return 0;
    }
}

internal sealed record Request(string Method, string Url, int Status, long Size, string? Referrer, string Label);

internal enum ActorKind { Normal, Monitor, Attack }

internal sealed class Actor(string ip, string userAgent, IEnumerator<(TimeSpan Delay, Request Request)> steps, ActorKind kind)
{
    public string Ip { get; } = ip;
    public string UserAgent { get; } = userAgent;
    public IEnumerator<(TimeSpan Delay, Request Request)> Steps { get; } = steps;
    public ActorKind Kind { get; } = kind;
}

internal sealed class SyntheticLog(int seed, double attackRatio)
{
    private const string Site = "https://shop.example.com";
    private const int NormalSessions = 40;
    private readonly Random _rng = new(seed);
    private readonly DateTimeOffset _start = new(2026, 10, 5, 0, 0, 0, TimeSpan.FromHours(2));

    private static readonly string[] Browsers =
    [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
    ];

    private static readonly string[] Crawlers =
    [
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
        "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"
    ];

    private static readonly string[] Pages =
        ["/", "/products", "/products?category=wine", "/products?category=cheese", "/about", "/contact", "/blog", "/cart", "/checkout", "/account"];

    private static readonly string[] Words =
        ["wine", "cheese", "red wine", "gift box", "olive oil", "honey", "raki", "chocolate", "coffee", "tea", "vintage 2019", "organic"];

    // Benign but unusual search terms (hard negatives for signature rules).
    private static readonly string[] OddSearches =
        ["o'neill wine", "rock & roll mug", "<3 gift", "50% off", "select size", "drop shipping", "deals--", "c++ book", "1=1 offer", "script writing kit"];

    // ---- attack payloads: detectable ones first, evasive ones (missed by the default rules) marked with '*' ----
    private static readonly string[] SqliPayloads =
    [
        "1' OR '1'='1", "1 UNION SELECT NULL,NULL--", "1 UNION ALL SELECT username,password FROM users--", "1' AND SLEEP(5)--",
        "1 AND 1=1", "1' or 1=1-- -", "1; DROP TABLE users", "1' UNION SELECT table_name FROM information_schema.tables--",
        "1 AND BENCHMARK(5000000,MD5(1))", "1') OR ('1'='1",
        "*1 AND 5821=5821", "*1;WAITFOR DELAY '0:0:5'", "*1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))#",
        "*1 /*!50000UNION*/ /*!50000SELECT*/ 1,2", "*1' || pg_sleep(5)--", "*1 OR 'a'='a'"
    ];

    private static readonly string[] XssPayloads =
    [
        "<script>alert(1)</script>", "\"><script>alert(document.cookie)</script>", "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>", "javascript:alert(1)", "<body onload=alert('xss')>", "<iframe src=javascript:alert(1)>",
        "*<details open ontoggle=alert(1)>", "*<a href=\"jav&#x09;ascript:alert(1)\">x</a>", "*'-prompt(1)-'",
        "*<math><mtext><img src onerror=confirm(1)>"
    ];

    private static readonly string[] TraversalPayloads =
    [
        "../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/passwd", "..\\..\\..\\windows\\win.ini",
        "php://filter/convert.base64-encode/resource=index.php", "/proc/self/environ", "%252e%252e%252fetc%252fpasswd",
        "*/etc/hosts", "*..%c0%af..%c0%afetc/hosts", "*file:///var/www/html/config.php"
    ];

    private static readonly string[] EnumWords =
    [
        "admin", "administrator", "backup", "backups", "old", "test", "dev", "staging", "api", "v1", "v2", "config", "conf",
        ".git/HEAD", ".env", ".svn", "phpmyadmin", "pma", "wp-admin", "wp-login.php", "wp-content", "uploads", "images", "img",
        "css", "js", "static", "assets", "server-status", "cgi-bin", "login", "logs", "tmp", "temp", "db", "database", "sql",
        "dump.sql", "backup.zip", "site.tar.gz", "web.config", "robots.txt", "sitemap.xml", "private", "secret", "install",
        "setup", "console", "actuator", "actuator/health", "debug", "jenkins", "manager/html", "shell", "cmd", "upload.php"
    ];

    private static readonly string[] ToolAgents =
    [
        "curl/8.5.0", "python-requests/2.31.0", "Go-http-client/1.1", "Wget/1.21.4"
    ];

    public Dictionary<string, int> Write(string logPath, string labelsPath, int lines)
    {
        var stats = new Dictionary<string, int>();
        var queue = new PriorityQueue<Actor, DateTimeOffset>();
        int activeNormal = 0, activeAttacks = 0, attackLines = 0;

        // Advances an actor to its next request and queues it at (previous time + think/delay time).
        void Schedule(Actor actor, DateTimeOffset at)
        {
            if (actor.Steps.MoveNext())
                queue.Enqueue(actor, at + actor.Steps.Current.Delay);
            else if (actor.Kind == ActorKind.Attack) activeAttacks--;
            else if (actor.Kind == ActorKind.Normal) activeNormal--;
        }

        // Long-lived background actor: uptime monitor polling /health every minute.
        Schedule(new Actor(RandomIp(), "UptimeRobot/2.0 (http://www.uptimerobot.com/)", Monitor().GetEnumerator(), ActorKind.Monitor), _start);

        using var log = new StreamWriter(logPath, false, new UTF8Encoding(false), 1 << 16);
        using var lab = new StreamWriter(labelsPath, false, new UTF8Encoding(false), 1 << 16);
        lab.WriteLine("line,label");

        var now = _start;
        for (var line = 1; line <= lines;)
        {
            // Keep enough normal traffic going.
            while (activeNormal < NormalSessions)
            {
                activeNormal++;
                var crawler = _rng.NextDouble() < 0.04;
                var ua = crawler ? Pick(Crawlers) : Pick(Browsers);
                Schedule(new Actor(RandomIp(), ua, (crawler ? Crawl() : Session()).GetEnumerator(), ActorKind.Normal),
                    now + TimeSpan.FromSeconds(_rng.NextDouble() * 30));
            }
            // Start an attack campaign when attacks are below the requested share.
            if (activeAttacks < 3 && attackLines < attackRatio * line && _rng.NextDouble() < 0.02)
            {
                activeAttacks++;
                var (steps, ua) = Campaign();
                Schedule(new Actor(RandomIp(), ua, steps.GetEnumerator(), ActorKind.Attack), now + TimeSpan.FromSeconds(_rng.Next(1, 120)));
            }

            queue.TryDequeue(out var actor, out var at);
            now = at;
            var req = actor!.Steps.Current.Request;

            log.WriteLine(FormatLine(actor.Ip, now, req, actor.UserAgent));
            lab.Write(line.ToString(CultureInfo.InvariantCulture));
            lab.Write(',');
            lab.WriteLine(req.Label);
            stats[req.Label] = stats.GetValueOrDefault(req.Label) + 1;
            if (req.Label != "normal") attackLines++;
            line++;

            Schedule(actor, now);
        }
        return stats;
    }

    // ---------------- normal behaviour ----------------

    private IEnumerable<(TimeSpan, Request)> Session()
    {
        var pages = _rng.Next(2, 25);
        string? referrer = _rng.NextDouble() < 0.5 ? "https://www.google.com/" : null;
        var delay = TimeSpan.Zero;
        for (var i = 0; i < pages; i++)
        {
            var (url, status) = NextPage();
            yield return (delay, new Request("GET", url, status, status == 200 ? _rng.Next(3_000, 60_000) : 512, referrer, "normal"));

            // Page assets: fast, mostly cached
            var assets = status == 200 ? _rng.Next(0, 5) : 0;
            for (var k = 0; k < assets; k++)
            {
                var asset = Pick(["/css/site.css", "/js/app.js", "/img/logo.png", $"/img/products/{_rng.Next(1, 300)}.jpg", "/favicon.ico"]);
                var cached = _rng.NextDouble() < 0.4;
                var missing = asset == "/favicon.ico" && _rng.NextDouble() < 0.3;
                yield return (Ms(30, 600), new Request("GET", asset, missing ? 404 : cached ? 304 : 200,
                    cached || missing ? 0 : _rng.Next(1_000, 250_000), Site + url, "normal"));
            }

            // Occasionally log in (sometimes with a typo first)
            if (_rng.NextDouble() < 0.06)
            {
                yield return (Sec(2, 10), new Request("GET", "/login", 200, 4_200, Site + url, "normal"));
                var failures = _rng.NextDouble() < 0.3 ? _rng.Next(1, 4) : 0;
                for (var f = 0; f < failures; f++)
                    yield return (Sec(4, 20), new Request("POST", "/login", 200, 4_350, Site + "/login", "normal"));
                yield return (Sec(4, 15), new Request("POST", "/login", 302, 0, Site + "/login", "normal"));
            }

            referrer = Site + url;
            delay = Think();
        }
    }

    private (string Url, int Status) NextPage()
    {
        var r = _rng.NextDouble();
        if (r < 0.35) return ($"/products/{_rng.Next(1, 300)}", 200);
        if (r < 0.50)
        {
            var term = _rng.NextDouble() < 0.02 ? Pick(OddSearches) : Pick(Words);
            return ("/search?q=" + Uri.EscapeDataString(term).Replace("%20", "+"), 200);
        }
        if (r < 0.58) return ($"/blog/{Pick(["harvest-2026", "how-to-pair-wine", "our-story", "new-arrivals", "christmas-gifts"])}", 200);
        if (r < 0.985) return (Pick(Pages), 200);
        return ($"/products/{_rng.Next(300, 400)}", 404); // broken link
    }

    private IEnumerable<(TimeSpan, Request)> Crawl()
    {
        yield return (TimeSpan.Zero, new Request("GET", "/robots.txt", 200, 120, null, "normal"));
        yield return (Sec(1, 3), new Request("GET", "/sitemap.xml", 200, 18_000, null, "normal"));
        var n = _rng.Next(40, 600);
        for (var i = 0; i < n; i++)
        {
            var old = _rng.NextDouble() < 0.06;
            var url = old ? $"/catalog/item-{_rng.Next(1, 999)}.html" : $"/products/{_rng.Next(1, 300)}";
            yield return (Sec(1, 6), new Request("GET", url, old ? 404 : 200, old ? 512 : _rng.Next(3_000, 60_000), null, "normal"));
        }
    }

    private IEnumerable<(TimeSpan, Request)> Monitor()
    {
        while (true)
            yield return (TimeSpan.FromSeconds(60), new Request("GET", "/health", 200, 2, null, "normal"));
    }

    // ---------------- attacks ----------------

    private (IEnumerable<(TimeSpan, Request)> Steps, string UserAgent) Campaign()
    {
        var r = _rng.Next(100);
        return r switch
        {
            < 20 => Sqli(),
            < 30 => (Xss(), Pick(Browsers)),
            < 45 => Traversal(),
            < 60 => BruteForce(),
            < 85 => DirEnum(),
            _ => (Scanner(), "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:" + _rng.Next(1, 9999).ToString("000000") + ")")
        };
    }

    private (IEnumerable<(TimeSpan, Request)>, string) Sqli()
    {
        // 30% spoof a browser user agent (sqlmap --random-agent), which hides it from the scanner UA rule.
        var ua = _rng.NextDouble() < 0.7 ? "sqlmap/1.8.3#stable (https://sqlmap.org)" : Pick(Browsers);
        return (Steps(), ua);

        IEnumerable<(TimeSpan, Request)> Steps()
        {
            // Light reconnaissance first: these requests are benign.
            yield return (TimeSpan.Zero, new Request("GET", "/products/12", 200, 14_000, null, "normal"));
            var param = Pick(["/products?id=", "/search?q=", "/products?category="]);
            var n = _rng.Next(30, 400);
            for (var i = 0; i < n; i++)
                yield return (Ms(150, 1500), new Request("GET", param + Payload(SqliPayloads), _rng.NextDouble() < 0.2 ? 500 : 200,
                    _rng.Next(500, 15_000), null, "sqli"));
        }
    }

    private IEnumerable<(TimeSpan, Request)> Xss()
    {
        var n = _rng.Next(10, 80);
        var param = Pick(["/search?q=", "/contact?message=", "/products?category="]);
        for (var i = 0; i < n; i++)
            yield return (i == 0 ? TimeSpan.Zero : Sec(1, 12), new Request("GET", param + Payload(XssPayloads), 200, _rng.Next(3_000, 12_000), Site + "/search", "xss"));
    }

    private (IEnumerable<(TimeSpan, Request)>, string) Traversal()
    {
        var ua = _rng.NextDouble() < 0.5 ? Pick(ToolAgents) : Pick(Browsers);
        return (Steps(), ua);

        IEnumerable<(TimeSpan, Request)> Steps()
        {
            var n = _rng.Next(10, 120);
            var param = Pick(["/download?file=", "/index.php?page=", "/static/", "/image?path="]);
            for (var i = 0; i < n; i++)
                yield return (Ms(300, 3000), new Request("GET", param + Payload(TraversalPayloads, encode: false),
                    _rng.NextDouble() < 0.7 ? 400 : 200, _rng.Next(200, 3_000), null, "traversal"));
        }
    }

    private (IEnumerable<(TimeSpan, Request)>, string) BruteForce()
    {
        var ua = Pick(["Mozilla/5.0 (Hydra)", "python-requests/2.31.0", Browsers[0]]);
        var slow = _rng.NextDouble() < 0.2; // low-and-slow: stays under 20 attempts per minute
        var path = Pick(["/login", "/login", "/wp-login.php", "/api/auth/token"]);
        return (Steps(), ua);

        IEnumerable<(TimeSpan, Request)> Steps()
        {
            var n = _rng.Next(25, 300);
            for (var i = 0; i < n; i++)
            {
                var success = i == n - 1 && _rng.NextDouble() < 0.1;
                yield return (slow ? Sec(5, 15) : Ms(300, 2500),
                    new Request("POST", path, success ? 302 : 200, success ? 0 : 4_350, Site + "/login", "bruteforce"));
            }
        }
    }

    private (IEnumerable<(TimeSpan, Request)>, string) DirEnum()
    {
        var ua = _rng.NextDouble() < 0.7
            ? Pick(["gobuster/3.6", "DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)", "Fuzz Faster U Fool v2.1.0"])
            : Pick(Browsers);
        return (Steps(), ua);

        IEnumerable<(TimeSpan, Request)> Steps()
        {
            var n = _rng.Next(150, 1500);
            var ext = Pick(["", ".php", ".bak", ".html", ".zip"]);
            for (var i = 0; i < n; i++)
            {
                var word = i < EnumWords.Length ? EnumWords[i] : $"{Pick(EnumWords)}{_rng.Next(1, 99)}";
                var r = _rng.NextDouble();
                var status = r < 0.92 ? 404 : r < 0.96 ? 403 : r < 0.98 ? 301 : 200;
                yield return (Ms(20, 250), new Request("GET", "/" + word + ext, status, status == 404 ? 512 : _rng.Next(200, 5_000), null, "direnum"));
            }
        }
    }

    private IEnumerable<(TimeSpan, Request)> Scanner()
    {
        var n = _rng.Next(300, 1500);
        for (var i = 0; i < n; i++)
        {
            var r = _rng.NextDouble();
            var url = r < 0.6 ? "/" + Pick(EnumWords) + Pick(["", ".php", ".asp", ".cgi", "/"])
                : r < 0.75 ? "/index.php?page=" + Payload(TraversalPayloads, encode: false)
                : r < 0.9 ? "/search?q=" + Payload(XssPayloads)
                : "/cgi-bin/" + Pick(["test.cgi", "php.cgi", "printenv", "awstats.pl"]);
            yield return (Ms(30, 400), new Request(Pick(["GET", "GET", "GET", "HEAD", "OPTIONS"]), url,
                _rng.NextDouble() < 0.85 ? 404 : 200, 512, null, "scanner"));
        }
    }

    // ---------------- helpers ----------------

    private string Payload(string[] list, bool encode = true)
    {
        var p = Pick(list).TrimStart('*');
        if (!encode)
            return p.Replace(" ", "%20").Replace("\"", "%22");
        // Mix of encodings as seen in real logs: fully encoded, '+' for spaces, or double-encoded.
        return _rng.NextDouble() switch
        {
            < 0.6 => Uri.EscapeDataString(p),
            < 0.9 => Uri.EscapeDataString(p).Replace("%20", "+"),
            _ => Uri.EscapeDataString(Uri.EscapeDataString(p))
        };
    }

    private string FormatLine(string ip, DateTimeOffset t, Request r, string ua)
    {
        var offset = t.Offset;
        var tz = (offset < TimeSpan.Zero ? "-" : "+") + offset.ToString("hhmm", CultureInfo.InvariantCulture);
        var time = t.ToString("dd/MMM/yyyy:HH:mm:ss", CultureInfo.InvariantCulture) + " " + tz;
        var size = r.Size > 0 ? r.Size.ToString(CultureInfo.InvariantCulture) : "-";
        return $"{ip} - - [{time}] \"{r.Method} {Esc(r.Url)} HTTP/1.1\" {r.Status} {size} \"{Esc(r.Referrer ?? "-")}\" \"{Esc(ua)}\"";
    }

    private static string Esc(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");

    private string RandomIp()
    {
        while (true)
        {
            int a = _rng.Next(1, 224), b = _rng.Next(0, 256);
            if (a is 10 or 127 || (a == 172 && b is >= 16 and <= 31) || (a == 192 && b == 168) || (a == 169 && b == 254) || a == 100)
                continue;
            return $"{a}.{b}.{_rng.Next(0, 256)}.{_rng.Next(1, 255)}";
        }
    }

    private T Pick<T>(IReadOnlyList<T> items) => items[_rng.Next(items.Count)];
    private TimeSpan Ms(int min, int max) => TimeSpan.FromMilliseconds(_rng.Next(min, max));
    private TimeSpan Sec(double min, double max) => TimeSpan.FromSeconds(min + _rng.NextDouble() * (max - min));

    // Think time between pages: exponential with a 20 s mean, capped at 5 minutes.
    private TimeSpan Think() => TimeSpan.FromSeconds(Math.Min(300, 1 - 20 * Math.Log(1 - _rng.NextDouble())));
}
