using System.Data;
using System.Diagnostics;
using System.IO.Compression;
using System.Threading.Channels;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Services;

/// <summary>A unit of background work: parse + detect a new file, or only re-run detection on stored events.</summary>
public sealed record ProcessingJob(int LogFileId, bool DetectionOnly = false);

/// <summary>In-memory queue of log files waiting to be processed.</summary>
public sealed class LogProcessingQueue
{
    private readonly Channel<ProcessingJob> _channel = Channel.CreateUnbounded<ProcessingJob>();

    public ValueTask EnqueueAsync(int logFileId, CancellationToken ct = default) =>
        _channel.Writer.WriteAsync(new ProcessingJob(logFileId), ct);

    public ValueTask EnqueueDetectionAsync(int logFileId, CancellationToken ct = default) =>
        _channel.Writer.WriteAsync(new ProcessingJob(logFileId, DetectionOnly: true), ct);

    public IAsyncEnumerable<ProcessingJob> ReadAllAsync(CancellationToken ct) =>
        _channel.Reader.ReadAllAsync(ct);
}

/// <summary>
/// Background worker: reads an uploaded file line by line, parses it and bulk-inserts
/// the events into SQL Server. Runs outside the HTTP request so large files don't time out.
/// </summary>
public sealed class LogProcessingWorker(
    LogProcessingQueue queue,
    IServiceScopeFactory scopeFactory,
    ILogParser parser,
    LogFileStorage storage,
    ILogger<LogProcessingWorker> logger) : BackgroundService
{
    private const int BatchSize = 5000;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await RequeueUnfinishedAsync(stoppingToken);

        await foreach (var job in queue.ReadAllAsync(stoppingToken))
        {
            var id = job.LogFileId;
            try
            {
                if (job.DetectionOnly)
                    await AnalyzeAsync(id, Stopwatch.StartNew(), parseMs: null, stoppingToken);
                else
                    await ProcessAsync(id, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Processing of log file {Id} failed", id);
                await MarkFailedAsync(id, ex.Message);
            }
        }
    }

    // Files left unfinished when the app stopped are picked up again on startup:
    // Pending/Processing are parsed again, Analyzing only needs detection (events are already stored).
    private async Task RequeueUnfinishedAsync(CancellationToken ct)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var files = await db.LogFiles
            .Where(f => f.Status == LogFileStatus.Pending || f.Status == LogFileStatus.Processing
                        || f.Status == LogFileStatus.Analyzing)
            .Select(f => new { f.Id, f.Status })
            .ToListAsync(ct);
        foreach (var f in files)
        {
            if (f.Status == LogFileStatus.Analyzing)
                await queue.EnqueueDetectionAsync(f.Id, ct);
            else
                await queue.EnqueueAsync(f.Id, ct);
        }
    }

    private async Task ProcessAsync(int id, CancellationToken ct)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        var file = await db.LogFiles.AsNoTracking().FirstOrDefaultAsync(f => f.Id == id, ct);
        if (file is null)
            return;

        var path = storage.GetPath(file);
        if (!File.Exists(path))
        {
            await MarkFailedAsync(id, "Uploaded file not found on disk.");
            return;
        }

        // Remove results from an earlier (or interrupted) run. Evidence first: it references events.
        await db.AlertEvidence.Where(e => e.Alert!.LogFileId == id).ExecuteDeleteAsync(ct);
        await db.Alerts.Where(a => a.LogFileId == id).ExecuteDeleteAsync(ct);
        await db.LogEvents.Where(e => e.LogFileId == id).ExecuteDeleteAsync(ct);
        await db.LogFiles.Where(f => f.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(f => f.Status, LogFileStatus.Processing)
            .SetProperty(f => f.TotalLines, 0)
            .SetProperty(f => f.ParsedLines, 0)
            .SetProperty(f => f.FailedLines, 0)
            .SetProperty(f => f.ErrorMessage, (string?)null), ct);

        var sw = Stopwatch.StartNew();
        int total = 0, parsed = 0, failed = 0, lineNumber = 0;

        await using var fileStream = File.OpenRead(path);
        Stream input = LogFileStorage.IsGzip(file.FileName)
            ? new GZipStream(fileStream, CompressionMode.Decompress)
            : fileStream;
        using var reader = new StreamReader(input);

        // TableLock: one bulk-update lock instead of row locks -> much faster large imports.
        using var bulk = new SqlBulkCopy(db.Database.GetConnectionString(), SqlBulkCopyOptions.TableLock)
        {
            DestinationTableName = "LogEvents",
            BatchSize = BatchSize,
            BulkCopyTimeout = 0
        };
        var table = CreateEventTable();
        foreach (DataColumn c in table.Columns)
            bulk.ColumnMappings.Add(c.ColumnName, c.ColumnName);

        string? line;
        while ((line = await reader.ReadLineAsync(ct)) is not null)
        {
            lineNumber++;
            if (string.IsNullOrWhiteSpace(line))
                continue;
            total++;

            if (parser.TryParse(line, out var p) && p is not null)
            {
                parsed++;
                table.Rows.Add(
                    id,
                    lineNumber,
                    Cut(p.ClientIp, 45),
                    p.Timestamp,
                    Cut(p.Method, 16),
                    Cut(p.Url, 4000),
                    (object?)Cut(p.Protocol, 16) ?? DBNull.Value,
                    p.StatusCode,
                    (object?)p.ResponseSize ?? DBNull.Value,
                    (object?)Cut(p.Referrer, 2000) ?? DBNull.Value,
                    (object?)Cut(p.UserAgent, 1000) ?? DBNull.Value,
                    Cut(line, 8000));
            }
            else
            {
                failed++;
            }

            if (table.Rows.Count >= BatchSize)
            {
                await bulk.WriteToServerAsync(table, ct);
                table.Clear();
                await UpdateProgressAsync(db, id, total, parsed, failed, ct);
            }
        }

        if (table.Rows.Count > 0)
            await bulk.WriteToServerAsync(table, ct);

        var parseMs = sw.ElapsedMilliseconds;
        await db.LogFiles.Where(f => f.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(f => f.Status, LogFileStatus.Analyzing)
            .SetProperty(f => f.TotalLines, total)
            .SetProperty(f => f.ParsedLines, parsed)
            .SetProperty(f => f.FailedLines, failed)
            .SetProperty(f => f.ParseMilliseconds, parseMs), ct);
        logger.LogInformation(
            "Log file {Id} ({Name}): {Parsed}/{Total} lines parsed, {Failed} failed, in {Ms} ms ({Rate:N0} lines/s)",
            id, file.FileName, parsed, total, failed, parseMs,
            total / Math.Max(sw.Elapsed.TotalSeconds, 0.001));

        await AnalyzeAsync(id, sw, parseMs, ct);
    }

    /// <summary>
    /// Detection + enrichment on the stored events of one file. Used after parsing and for "Re-run detection".
    /// Threat-intel lookups run after the file is marked Completed, because rate-limited providers can be slow.
    /// </summary>
    private async Task AnalyzeAsync(int id, Stopwatch sw, long? parseMs, CancellationToken ct)
    {
        using var scope = scopeFactory.CreateScope();
        var sp = scope.ServiceProvider;
        var db = sp.GetRequiredService<AppDbContext>();

        await db.LogFiles.Where(f => f.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(f => f.Status, LogFileStatus.Analyzing), ct);

        // Run the detection rules on the parsed events.
        var detectSw = Stopwatch.StartNew();
        var alerts = await sp.GetRequiredService<DetectionEngine>().RunAsync(id, ct);
        detectSw.Stop();

        // Offline country / city lookup for the attacker IPs. Never fails the whole file.
        try
        {
            await sp.GetRequiredService<IpEnrichmentService>().EnrichAlertSourcesAsync(id, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "GeoIP enrichment failed for log file {Id}", id);
        }

        await db.LogFiles.Where(f => f.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(f => f.Status, LogFileStatus.Completed)
            .SetProperty(f => f.ProcessedAt, DateTime.UtcNow)
            .SetProperty(f => f.DetectionMilliseconds, detectSw.ElapsedMilliseconds), ct);

        sw.Stop();
        logger.LogInformation("Log file {Id} completed: {Alerts} alerts, total {Ms} ms (parse {ParseMs} ms, detection {DetectMs} ms)",
            id, alerts, sw.ElapsedMilliseconds, parseMs?.ToString() ?? "-", detectSw.ElapsedMilliseconds);

        // Reputation lookups (AbuseIPDB, GreyNoise, VirusTotal) + GreyNoise severity rule. Best effort.
        try
        {
            var ti = await sp.GetRequiredService<ThreatIntelService>().RunForLogFileAsync(id, ct);
            if (ti.Lookups > 0 || ti.Downgraded > 0)
                logger.LogInformation("Threat intel for log file {Id}: {Lookups} lookups, {Downgraded} alerts lowered",
                    id, ti.Lookups, ti.Downgraded);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Threat-intel enrichment failed for log file {Id}", id);
        }
    }

    private static Task UpdateProgressAsync(AppDbContext db, int id, int total, int parsed, int failed, CancellationToken ct) =>
        db.LogFiles.Where(f => f.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(f => f.TotalLines, total)
            .SetProperty(f => f.ParsedLines, parsed)
            .SetProperty(f => f.FailedLines, failed), ct);

    private async Task MarkFailedAsync(int id, string message)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await db.LogFiles.Where(f => f.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(f => f.Status, LogFileStatus.Failed)
            .SetProperty(f => f.ErrorMessage, Cut(message, 2000)));
    }

    // Column names must match the LogEvents table created by the migration.
    private static DataTable CreateEventTable()
    {
        var t = new DataTable();
        t.Columns.Add("LogFileId", typeof(int));
        t.Columns.Add("LineNumber", typeof(int));
        t.Columns.Add("ClientIp", typeof(string));
        t.Columns.Add("Timestamp", typeof(DateTimeOffset));
        t.Columns.Add("Method", typeof(string));
        t.Columns.Add("Url", typeof(string));
        t.Columns.Add("Protocol", typeof(string));
        t.Columns.Add("StatusCode", typeof(int));
        t.Columns.Add("ResponseSize", typeof(long));
        t.Columns.Add("Referrer", typeof(string));
        t.Columns.Add("UserAgent", typeof(string));
        t.Columns.Add("RawLine", typeof(string));
        return t;
    }

    private static string? Cut(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];
}
