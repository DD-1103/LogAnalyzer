using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LogAnalyzer.Tests;

/// <summary>Regression tests for the processing fixes of the 2026-11-17 audit (findings 01, 05, 06, 08).</summary>
public class ProcessingFixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // ---- 01: threshold evidence is linear and identical to the old algorithm ----

    /// <summary>The original (quadratic) algorithm, kept as the reference for the property test.</summary>
    private static Dictionary<string, HashSet<long>> ReferenceThreshold(IEnumerable<DetectionEvent> events, int threshold, TimeSpan window)
    {
        var windows = new Dictionary<string, Queue<(DateTimeOffset Ts, long Id)>>();
        var hits = new Dictionary<string, HashSet<long>>();
        foreach (var e in events)
        {
            if (e.StatusCode != 404)
                continue;
            if (!windows.TryGetValue(e.ClientIp, out var w))
                windows[e.ClientIp] = w = new Queue<(DateTimeOffset, long)>();
            w.Enqueue((e.Timestamp, e.Id));
            while (e.Timestamp - w.Peek().Ts > window)
                w.Dequeue();
            if (w.Count >= threshold)
            {
                if (!hits.TryGetValue(e.ClientIp, out var set))
                    hits[e.ClientIp] = set = [];
                foreach (var (_, id) in w)
                    set.Add(id);
            }
        }
        return hits;
    }

    private static DetectionCore ThresholdCore(int threshold, int windowSeconds)
    {
        var rule = new DetectionRule
        {
            Id = 1, Name = "t", Kind = RuleKind.Threshold, AttackType = AttackType.DirectoryEnumeration,
            Severity = Severity.Medium, StatusFilter = 404, Threshold = threshold, WindowSeconds = windowSeconds
        };
        return new DetectionCore([DetectionCore.TryCompile(rule, out var error) ?? throw new InvalidOperationException(error)]);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public void Threshold_EvidenceMatchesReferenceAlgorithm(int seed)
    {
        var rnd = new Random(seed);
        var events = new List<DetectionEvent>();
        var t = T0;
        for (var i = 1; i <= 4000; i++)
        {
            // Bursts and pauses so windows fill, drain below the threshold and cross it again.
            t = t.AddMilliseconds(rnd.Next(10) < 8 ? rnd.Next(0, 800) : rnd.Next(5_000, 90_000));
            var ip = "10.0.0." + rnd.Next(1, 4);
            var status = rnd.Next(10) < 8 ? 404 : 200;
            events.Add(new DetectionEvent(i, ip, t, "GET", "/p" + i, status, "ua", null));
        }

        var threshold = rnd.Next(3, 30);
        var windowSeconds = rnd.Next(5, 60);
        var core = ThresholdCore(threshold, windowSeconds);
        foreach (var e in events)
            core.Process(e);

        var expected = ReferenceThreshold(events, threshold, TimeSpan.FromSeconds(windowSeconds));
        Assert.Equal(expected.Count, core.Hits.Count);
        foreach (var hit in core.Hits)
        {
            Assert.True(expected[hit.Ip].SetEquals(hit.EventIds), $"evidence differs for {hit.Ip}");
            var times = events.Where(e => hit.EventIds.Contains(e.Id)).Select(e => e.Timestamp).ToList();
            Assert.Equal(times.Min(), hit.First);
            Assert.Equal(times.Max(), hit.Last);
        }
    }

    [Fact]
    public void Threshold_FastScannerIsLinear()
    {
        // 200k 404s from one IP at 200 req/s with the default rule (50 per 60 s): ~34 s before the fix.
        var core = new DetectionCore([DetectionCore.TryCompile(
            DbSeeder.DefaultRules().Single(r => r.Name == "Directory enumeration"), out _)!]);
        var sw = Stopwatch.StartNew();
        for (var i = 0; i < 200_000; i++)
            core.Process(new DetectionEvent(i + 1, "203.0.113.9", T0.AddMilliseconds(i * 5), "GET", "/x" + i, 404, "gobuster", null));
        sw.Stop();

        Assert.Equal(200_000, Assert.Single(core.Hits).EventIds.Count);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(4), $"took {sw.Elapsed.TotalSeconds:F1} s");
    }

    // ---- 05: bounded input ----

    [Fact]
    public void LimitedReadStream_ThrowsAtTheLimit()
    {
        using var s = new LimitedReadStream(new MemoryStream(new byte[10_000]), 4096, "too big");
        var buffer = new byte[1024];
        var ex = Assert.Throws<LogLimitExceededException>(() => { while (s.Read(buffer, 0, buffer.Length) > 0) { } });
        Assert.Equal("too big", ex.Message);
        Assert.True(s.BytesRead <= 4096 + buffer.Length);
    }

    [Fact]
    public async Task GzipBomb_StopsAtTheDecompressedLimit()
    {
        var compressed = new MemoryStream();
        await using (var gz = new GZipStream(compressed, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            var line = Encoding.ASCII.GetBytes("1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] \"GET /?id=1 HTTP/1.1\" 200 1 \"-\" \"sqlmap\"\n");
            for (var i = 0; i < 200_000; i++)
                gz.Write(line);
        }
        compressed.Position = 0;
        Assert.True(compressed.Length < 1_000_000);   // ~19 MB of text in a few hundred KB

        using var limited = new LimitedReadStream(new GZipStream(compressed, CompressionMode.Decompress), 1_000_000, "bomb");
        using var reader = new BoundedLineReader(new StreamReader(limited), 16 * 1024);
        var lines = 0;
        await Assert.ThrowsAsync<LogLimitExceededException>(async () =>
        {
            while (await reader.ReadLineAsync(CancellationToken.None) is not null)
                lines++;
        });
        Assert.InRange(lines, 1, 20_000);
    }

    private static async Task<List<BoundedLine>> ReadAll(string text, int max)
    {
        using var reader = new BoundedLineReader(new StringReader(text), max);
        var list = new List<BoundedLine>();
        while (await reader.ReadLineAsync(CancellationToken.None) is { } l)
            list.Add(l);
        return list;
    }

    [Fact]
    public async Task BoundedLineReader_SkipsTheRestOfOverlongLines()
    {
        var huge = new string('A', 10 * 1024 * 1024);
        var lines = await ReadAll(huge + "\nshort line\n", 16 * 1024);

        Assert.Equal(2, lines.Count);
        Assert.True(lines[0].TooLong);
        Assert.Equal(16 * 1024, lines[0].Text.Length);
        Assert.Equal(new BoundedLine("short line", false), lines[1]);
    }

    [Theory]
    [InlineData("a\nb\n", new[] { "a", "b" })]
    [InlineData("a\r\nb", new[] { "a", "b" })]
    [InlineData("a\rb\r\n\r\nc", new[] { "a", "b", "", "c" })]
    [InlineData("", new string[0])]
    [InlineData("\n", new[] { "" })]
    public async Task BoundedLineReader_MatchesStreamReaderLineEnds(string text, string[] expected)
    {
        var lines = await ReadAll(text, 100);
        Assert.Equal(expected, lines.Select(l => l.Text).ToArray());

        var reference = new List<string>();
        using var sr = new StringReader(text);
        while (sr.ReadLine() is { } l)
            reference.Add(l);
        Assert.Equal(reference, lines.Select(l => l.Text));
    }

    [Fact]
    public async Task BoundedLineReader_HandlesCrLfAcrossBufferBoundary()
    {
        // The internal buffer is 64K chars: put \r as its last char and \n as the first of the next read.
        var first = new string('x', 64 * 1024 - 1);
        var lines = await ReadAll(first + "\r\nnext", 128 * 1024);
        Assert.Equal([first, "next"], lines.Select(l => l.Text));
    }

    // ---- 06: the worker survives a dead database ----

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (Entries)
                Entries.Add((logLevel, formatter(state, exception)));
        }

        public int Count(Func<(LogLevel Level, string Message), bool> predicate)
        {
            lock (Entries)
                return Entries.Count(predicate);
        }
    }

    private sealed class FakeEnv : IWebHostEnvironment
    {
        public string WebRootPath { get; set; } = Path.GetTempPath();
        public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
        public string ApplicationName { get; set; } = "test";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
        public string ContentRootPath { get; set; } = Path.GetTempPath();
        public string EnvironmentName { get; set; } = "Test";
    }

    private static async Task WaitUntil(Func<bool> condition, TimeSpan timeout)
    {
        var sw = Stopwatch.StartNew();
        while (!condition() && sw.Elapsed < timeout)
            await Task.Delay(50);
    }

    [Fact]
    public async Task Worker_KeepsRunningWhenTheDatabaseIsDown()
    {
        var services = new ServiceCollection();
        // Nothing listens on port 1: every database call fails, including MarkFailed in the catch block.
        services.AddDbContext<AppDbContext>(o => o.UseSqlServer(
            "Server=tcp:127.0.0.1,1;Database=none;Integrated Security=true;Encrypt=False;Connect Timeout=2"));
        await using var provider = services.BuildServiceProvider();

        var queue = new LogProcessingQueue();
        var logger = new CapturingLogger<LogProcessingWorker>();
        var worker = new LogProcessingWorker(queue, new ThreatIntelQueue(), provider.GetRequiredService<IServiceScopeFactory>(),
            new CombinedLogParser(), new LogFileStorage(new FakeEnv()), Options.Create(new ProcessingOptions()), logger);

        await queue.EnqueueAsync(1);
        await queue.EnqueueDetectionAsync(2);
        await queue.EnqueueDeleteAsync(3);
        await worker.StartAsync(CancellationToken.None);

        await WaitUntil(() => logger.Count(e => e.Message.StartsWith("Could not mark log file")) >= 3, TimeSpan.FromSeconds(60));
        Assert.False(worker.ExecuteTask!.IsCompleted, "the worker loop must still be running");
        Assert.Equal(3, logger.Count(e => e.Level == LogLevel.Error && e.Message.Contains(" of log file ") && e.Message.EndsWith("failed")));
        Assert.Equal(1, logger.Count(e => e.Message.StartsWith("Could not re-queue")));

        await worker.StopAsync(CancellationToken.None);
        Assert.True(worker.ExecuteTask.IsCompletedSuccessfully);
    }

    [Fact]
    public void Worker_UserMessagesHideTechnicalDetails()
    {
        var sql = new InvalidOperationException(@"Login failed for user 'DANIEL\User' at C:\secret\path");
        var msg = LogProcessingWorker.UserMessage(ProcessingJobKind.Parse, sql);
        Assert.DoesNotContain("DANIEL", msg);
        Assert.DoesNotContain(@"C:\", msg);
        Assert.Equal("too many lines", LogProcessingWorker.UserMessage(ProcessingJobKind.Parse, new LogLimitExceededException("too many lines")));
        Assert.Contains("gzip", LogProcessingWorker.UserMessage(ProcessingJobKind.Parse, new InvalidDataException("bad magic")));
    }

    // ---- 08: threat intel runs in its own worker ----

    private sealed class FakeThreatIntel(Func<int, CancellationToken, Task> run) : ILogFileThreatIntel
    {
        public async Task<ThreatIntelRunSummary> RunForLogFileAsync(int logFileId, CancellationToken ct)
        {
            await run(logFileId, ct);
            return new ThreatIntelRunSummary(1, 0);
        }
    }

    [Fact]
    public async Task ThreatIntelWorker_ContinuesAfterAFailingFile()
    {
        var done = new List<int>();
        var services = new ServiceCollection();
        services.AddScoped<ILogFileThreatIntel>(_ => new FakeThreatIntel((id, _) =>
        {
            if (id == 1)
                throw new HttpRequestException("provider down");
            lock (done)
                done.Add(id);
            return Task.CompletedTask;
        }));
        await using var provider = services.BuildServiceProvider();

        var queue = new ThreatIntelQueue();
        var logger = new CapturingLogger<ThreatIntelWorker>();
        var worker = new ThreatIntelWorker(queue, provider.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new ProcessingOptions()), logger);
        await worker.StartAsync(CancellationToken.None);
        await queue.EnqueueAsync(1);
        await queue.EnqueueAsync(2);

        await WaitUntil(() => { lock (done) return done.Contains(2); }, TimeSpan.FromSeconds(10));
        Assert.Contains(2, done);
        Assert.Equal(1, logger.Count(e => e.Level == LogLevel.Warning));
        await worker.StopAsync(CancellationToken.None);
    }
}
