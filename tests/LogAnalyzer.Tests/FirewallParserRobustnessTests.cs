using System.Diagnostics;
using System.Text;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.Services.LogFormats;

namespace LogAnalyzer.Tests;

/// <summary>Format detection, mixed files, and deterministic fuzzing of every parser with hostile lines (2026-11-25).</summary>
public class FirewallParserRobustnessTests
{
    private static readonly LogParseContext Ctx = FirewallFormatVerificationTests.Ctx;

    private static string Samples
    {
        get
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "samples", "firewall")))
                dir = dir.Parent;
            return Path.Combine(dir!.FullName, "samples");
        }
    }

    // ------------------------------------------------------------------ detection and mixed files

    private static FormatDetection Detect(params string[] lines) => LogFormatDetector.Detect(lines, Ctx);

    [Fact]
    public void Web_logs_with_firewall_text_stay_web_logs()
    {
        var lines = Enumerable.Range(0, 20).Select(i =>
            $"203.0.113.{i} - - [21/Nov/2026:10:00:{i:00} +0000] \"GET /?srcip=1.2.3.4&dstip=5.6.7.8 srcip=1.2.3.4 dstip=5.6.7.8 action=deny type=traffic devid=1 date=2026-11-21 time=10:00:00 HTTP/1.1\" 200 12 \"-\" \"CEF:0|a|b|c|d|e|5|src=1.2.3.4 dst=5.6.7.8 %ASA-4-106023: Deny tcp src o:1.2.3.4/1 dst i:5.6.7.8/2\"").ToList();
        Assert.Equal("combined", LogFormatDetector.Detect(lines, Ctx).Format!.Id);
        // truncated lines in between
        for (var i = 0; i < 6; i++)
            lines.Add("203.0.113.9 - - [21/Nov/2026:10:00:00 +0000] \"GET /?srcip=1.2.3.4&dstip=5.6.7.8&action=deny srcip=1.2.3.4 dstip=5.6.7.8 action=deny date=2026-11-21 time=10:00:00");
        Assert.Equal("combined", LogFormatDetector.Detect(lines, Ctx).Format!.Id);
    }

    [Theory]
    [InlineData("{\"time\":\"2026-11-21T10:00:00Z\",\"clientip\":\"203.0.113.5\",\"serverip\":\"10.0.0.5\",\"method\":\"GET\",\"uri\":\"/\",\"status\":200,\"serverport\":443}")]
    [InlineData("{\"@timestamp\":\"2026-11-21T10:00:00Z\",\"source\":{\"ip\":\"203.0.113.5\"},\"destination\":{\"ip\":\"10.0.0.5\",\"port\":443},\"http\":{\"request\":{\"method\":\"GET\"},\"response\":{\"status_code\":200}},\"url\":{\"original\":\"/\"}}")]
    [InlineData("{\"ts\":1795255200,\"level\":\"info\",\"msg\":\"handled request\",\"request\":{\"remote_ip\":\"203.0.113.5\",\"remote_port\":\"51234\",\"proto\":\"HTTP/2.0\",\"method\":\"GET\",\"host\":\"a\",\"uri\":\"/\"},\"status\":200}")]
    [InlineData("time=2026-11-21T10:00:00Z level=info client_ip=203.0.113.5 server_ip=10.0.0.5 method=GET path=/ status=200")]
    [InlineData("the quick brown fox jumps over the lazy dog = 12 src maybe, dst maybe not")]
    public void Web_logs_in_json_or_logfmt_and_random_text_are_not_firewall_logs(string line) =>
        Assert.Null(Detect(line, line, line).Format);

    [Theory]
    [InlineData("cef", "Nov 21 10:00:00 fw CEF:0|Fortinet|FortiGate|7|1|deny|5|src=203.0.113.5 dst=10.0.0.5 dpt=22 act=deny devid=F logid=1 type=traffic")]
    [InlineData("leef", "Nov 21 10:00:00 fw LEEF:1.0|Check Point|VPN-1|1|Drop|src=203.0.113.5\tdst=10.0.0.5\tproduct=x\torigin=1.2.3.4\taction=Drop")]
    [InlineData("json", "{\"time\":\"2026-11-21T10:00:00Z\",\"src_ip\":\"203.0.113.5\",\"dst_ip\":\"10.0.0.5\",\"action\":\"deny\",\"log_type\":\"Firewall\",\"msg\":\"devid=1 type=traffic logid=1 srcip=1.2.3.4\"}")]
    [InlineData("keyvalue", "2026-11-21T10:00:00Z fw01 src=203.0.113.5 dst=10.0.0.5 action=deny proto=tcp dpt=22")]
    public void Neutral_formats_are_not_stolen_by_a_vendor_format(string id, string line) =>
        Assert.Equal(id, Detect(line, line, line).Format!.Id);

    private sealed class StubFormat(ParseOutcome outcome, int specificity, string id) : ILogFormat
    {
        public string Id => id;
        public string DisplayName => id;
        public LogSource Source => LogSource.Firewall;
        public int Specificity => specificity;
        public ILineParser CreateParser(LogParseContext context) => new StubParser(outcome, id);

        private sealed class StubParser(ParseOutcome outcome, string id) : ILineParser
        {
            public ParseOutcome Parse(string line, out ParsedLine? result)
            {
                result = outcome == ParseOutcome.Parsed ? ParsedLine.Network("203.0.113.5", DateTimeOffset.UnixEpoch, FirewallAction.Deny, id) : null;
                return outcome;
            }
        }
    }

    [Fact]
    public void Mixed_files_prefer_a_parsed_result_over_a_skipped_one()
    {
        var primary = new StubFormat(ParseOutcome.Failed, 100, "p");
        var parser = new MultiFormatParser(primary, Ctx, [new StubFormat(ParseOutcome.Skipped, 100, "skips"), new StubFormat(ParseOutcome.Parsed, 100, "reads")]);
        Assert.Equal(ParseOutcome.Parsed, parser.Parse("x", out var p));
        Assert.Equal("reads", p!.Url);

        // also when the main format skips the line as "one of its own" - but only for vendor / structured formats
        var skipping = new StubFormat(ParseOutcome.Skipped, 100, "p");
        Assert.Equal(ParseOutcome.Parsed, new MultiFormatParser(skipping, Ctx, [new StubFormat(ParseOutcome.Parsed, 100, "reads")]).Parse("x", out _));
        Assert.Equal(ParseOutcome.Skipped, new MultiFormatParser(skipping, Ctx, [new StubFormat(ParseOutcome.Parsed, 10, "generic")]).Parse("x", out _));
        // nobody reads it: skipped beats failed
        parser = new MultiFormatParser(primary, Ctx, [new StubFormat(ParseOutcome.Failed, 100, "f"), new StubFormat(ParseOutcome.Skipped, 100, "s")]);
        Assert.Equal(ParseOutcome.Skipped, parser.Parse("x", out _));
    }

    [Fact]
    public void The_generic_reader_never_overtakes_a_vendor_format_in_a_mixed_file()
    {
        var parser = new MultiFormatParser(LogFormatRegistry.Find("netfilter")!, Ctx);
        Assert.Equal(ParseOutcome.Parsed, parser.Parse("2026-11-21T10:00:00Z fw01 src=203.0.113.5 dst=10.0.0.5 action=deny proto=tcp dpt=22", out _));
        Assert.Equal(ParseOutcome.Parsed, parser.Parse("date=2026-11-21 time=10:00:00 devname=\"fw\" devid=\"F\" logid=\"1\" type=\"traffic\" srcip=203.0.113.5 dstip=10.0.0.5 action=\"deny\"", out _));
        Assert.Contains("Fortinet FortiGate", parser.UsedFormats.Keys);
    }

    [Fact]
    public void Every_sample_gives_the_same_events_through_the_mixed_parser_as_through_its_own_format()
    {
        foreach (var file in Directory.GetFiles(Path.Combine(Samples, "firewall"), "*.log"))
        {
            var lines = File.ReadAllLines(file);
            var format = LogFormatDetector.Detect(lines.Take(200).ToList(), Ctx).Format!;
            var own = format.CreateParser(Ctx);
            var mixed = new MultiFormatParser(format, Ctx);
            foreach (var line in lines)
            {
                var a = own.Parse(line, out var pa);
                var b = mixed.Parse(line, out var pb);
                if (a == ParseOutcome.Parsed)
                    Assert.Equal((a, pa), (b, pb));
                else
                    Assert.True(a == b || b == ParseOutcome.Parsed && a == ParseOutcome.Failed, $"{Path.GetFileName(file)}: {line}");
            }
        }
    }

    // ------------------------------------------------------------------ fuzzing

    private static List<string> SampleLines()
    {
        var lines = Directory.GetFiles(Path.Combine(Samples, "firewall"), "*.log").Order(StringComparer.Ordinal)
            .SelectMany(f => File.ReadAllLines(f).Take(60)).ToList();
        lines.AddRange(File.ReadAllLines(Path.Combine(Samples, "sample-access.log")).Take(60));
        return lines;
    }

    private static readonly string[] Nasty =
    [
        "\"", "'", "\\", "=", "[", "]", "(", ")", "|", ",", ";", ":", "%", "<", ">", "\t", "\0", "\u001b", "\r", "\n", "\ud800", "\udfff", "﻿",
        "99999999999999999999", "-1", "4294967296", "١٢٣", "Feb 30 10:00:00", "Feb 29 10:00:00", "0001-01-01T00:00:00+14:00", "9999-12-31T23:59:59-14:00",
        "+99:99", "tz=\"+1400\"", "date=0001-01-01", "time=00:00:00", "\\ud800", "{", "}", "{\"a\":", "::", "1.2.3.4", "->", "CEF:0|", "LEEF:2.0|", "%ASA-6-302013: ",
        "<999>", "<134>1 ", "%%01A/1/B(l):", "srcip=", "src=", "from ", " port ", "0x", "#Fields: ", "${srcaddr} ${dstaddr}", "message repeated 99999999999 times: ["
    ];

    private static string Mutate(Random rnd, string line, List<string> pool)
    {
        var sb = new StringBuilder(line);
        for (var k = rnd.Next(1, 6); k > 0; k--)
        {
            var at = rnd.Next(0, sb.Length + 1);
            switch (rnd.Next(7))
            {
                case 0:
                    sb.Insert(at, Nasty[rnd.Next(Nasty.Length)]);
                    break;
                case 1:
                    if (at < sb.Length)
                        sb.Remove(at, Math.Min(rnd.Next(1, 20), sb.Length - at));
                    break;
                case 2:
                    if (at < sb.Length)
                        sb[at] = (char)rnd.Next(0, 0x10000);
                    break;
                case 3:
                    if (at < sb.Length)
                        sb[at] = (char)rnd.Next(0, 128);
                    break;
                case 4:
                    sb.Length = at;
                    break;
                case 5:
                    var other = pool[rnd.Next(pool.Count)];
                    sb.Insert(at, other[..rnd.Next(0, other.Length + 1)]);
                    break;
                default:
                    for (var i = at; i < sb.Length; i++)
                        if (char.IsAsciiDigit(sb[i]))
                        {
                            sb[i] = (char)('0' + rnd.Next(10));
                            if (rnd.Next(3) == 0)
                                break;
                        }
                    break;
            }
        }
        return sb.Length > 16384 ? sb.ToString(0, 16384) : sb.ToString();
    }

    private static void AssertSane(string formatId, string line, ParseOutcome outcome, ParsedLine? p)
    {
        if (outcome != ParseOutcome.Parsed)
            return;
        Assert.NotNull(p);
        if (formatId == WebAccessLogFormat.FormatId)
            return;
        Assert.True(p.ClientIp == "-" || System.Net.IPAddress.TryParse(p.ClientIp, out _), $"{formatId}: '{p.ClientIp}' from {line}");
        Assert.True(p.DestinationIp is null || System.Net.IPAddress.TryParse(p.DestinationIp, out _), $"{formatId}: '{p.DestinationIp}'");
        Assert.InRange(p.Timestamp.UtcDateTime.Year, 1969, 2101);
        Assert.InRange(p.SourcePort ?? 0, 0, 65535);
        Assert.InRange(p.DestinationPort ?? 0, 0, 65535);
        Assert.DoesNotContain(p.Url, char.IsControl);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(14)]
    [InlineData(-12)]
    public void Mutated_sample_lines_never_throw_in_any_parser(int offsetHours)
    {
        var pool = SampleLines();
        var ctx = new LogParseContext(Ctx.ReferenceTime, TimeSpan.FromHours(offsetHours));
        var parsers = LogFormatRegistry.All.Select(f => (f.Id, Parser: f.CreateParser(ctx))).ToList();
        var rnd = new Random(42 + offsetHours);
        for (var i = 0; i < 4000; i++)
        {
            var line = Mutate(rnd, pool[rnd.Next(pool.Count)], pool);
            foreach (var (id, parser) in parsers)
            {
                ParseOutcome outcome;
                ParsedLine? p;
                try
                {
                    // the parser itself, without LogFormatDetector.SafeParse and without the key=value catch-all
                    outcome = parser is FirewallLineParser kv ? kv.ParseUnguarded(line, out p) : parser.Parse(line, out p);
                }
                catch (Exception ex)
                {
                    throw new Xunit.Sdk.XunitException($"{id} threw {ex} on: {line}");
                }
                AssertSane(id, line, outcome, p);
            }
        }
    }

    private static List<string> HostileLines(List<string> pool, int count)
    {
        const int Size = 16 * 1024;
        var rnd = new Random(1234);
        string[] fill =
        [
            "\"", "'", "\\", "\\\"", "=", "a=", "a='x ", "a=\"", "[", "]", "[]", "(", "(a", ")", "|", ",", ", ", ";", ": ", "<", ">", "->", " ", "\t", "\0", "\n", "0", "9", "1.",
            "::", "ab:", "%", "%%", "%ASA-", "%%01A/1/B(l):", "{", "{\"a\":", "[{", "CEF:0|", "src=1.2.3.4 ", " from ", " from 1.2.3.4 port 1", " to ", " IN=", "x: in:", "SRC=1 DST=2 ",
            "aaaaaaaa", "a,", "key:\"v\"; ", "\\\\", "-", "- ", "(a) ", " -> ", "/", "a/", "\ud800", "Peer IP=", "source-address=\"", "́", "(", "\\(", "Feb 29 ", "user IP = "
        ];
        var lines = new List<string>(count + 1);
        for (var i = 0; i < count; i++)
        {
            var start = pool[rnd.Next(pool.Count)];
            var sb = new StringBuilder(Size + 64).Append(start, 0, rnd.Next(0, start.Length + 1));
            var f1 = fill[rnd.Next(fill.Length)];
            var f2 = fill[rnd.Next(fill.Length)];
            var half = rnd.Next(sb.Length, Size);
            while (sb.Length < half)
                sb.Append(f1);
            if (rnd.Next(2) == 0)
                sb.Append("aaaa!");
            while (sb.Length < Size)
                sb.Append(rnd.Next(3) == 0 ? f1 : f2);
            lines.Add(sb.ToString(0, Size));
        }
        // key characters, one invalid character, then a run of "=" (quadratic in a careless CEF reader)
        for (var i = 0; i < 20; i++)
            lines.Add("CEF:0|a|b|c|d|e|5|msg=x " + new string('a', 8000) + "!" + new string('=', 8000));
        return lines;
    }

    [Fact]
    public void Hostile_16_KB_lines_are_handled_quickly()
    {
        var lines = HostileLines(SampleLines(), 2000);
        foreach (var format in LogFormatRegistry.All)
        {
            var parser = format.CreateParser(Ctx);
            var sw = Stopwatch.StartNew();
            foreach (var line in lines)
            {
                var outcome = parser.Parse(line, out var p);
                AssertSane(format.Id, "(hostile)", outcome, p);
            }
            // 2,000 lines = 32 MB; about a second per format in Debug
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(30), $"{format.Id}: {sw.Elapsed}");
        }
    }
}
