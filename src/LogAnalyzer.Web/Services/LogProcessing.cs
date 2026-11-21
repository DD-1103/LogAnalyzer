using System.Data;
using System.Data.Common;
using System.Diagnostics;
using System.IO.Compression;
using System.Threading.Channels;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

using LogAnalyzer.Web.Services.LogFormats;

namespace LogAnalyzer.Web.Services;

public enum ProcessingJobKind
{
    /// <summary>Parse the uploaded file, then detect.</summary>
    Parse,
    /// <summary>Only re-run detection on the stored events.</summary>
    Detect,
    /// <summary>Delete the file and all its data (in batches).</summary>
    Delete
}

/// <summary>A unit of background work for one log file.</summary>
public sealed record ProcessingJob(int LogFileId, ProcessingJobKind Kind = ProcessingJobKind.Parse);

/// <summary>In-memory queue of log files waiting to be processed.</summary>
public sealed class LogProcessingQueue
{
    private readonly Channel<ProcessingJob> _channel = Channel.CreateUnbounded<ProcessingJob>();

    public ValueTask EnqueueAsync(int logFileId, CancellationToken ct = default) =>
        _channel.Writer.WriteAsync(new ProcessingJob(logFileId), ct);

    public ValueTask EnqueueDetectionAsync(int logFileId, CancellationToken ct = default) =>
        _channel.Writer.WriteAsync(new ProcessingJob(logFileId, ProcessingJobKind.Detect), ct);

    public ValueTask EnqueueDeleteAsync(int logFileId, CancellationToken ct = default) =>
        _channel.Writer.WriteAsync(new ProcessingJob(logFileId, ProcessingJobKind.Delete), ct);

    public IAsyncEnumerable<ProcessingJob> ReadAllAsync(CancellationToken ct) =>
        _channel.Reader.ReadAllAsync(ct);
}

/// <summary>
/// Background worker: reads an uploaded file line by line, parses it and bulk-inserts
/// the events into SQL Server. Runs outside the HTTP request so large files don't time out.
/// The loop never throws: a failing job (or a failing database) marks the file Failed and the worker carries on,
/// so one problem can never stop the whole web app.
/// </summary>
public sealed class LogProcessingWorker(
    LogProcessingQueue queue,
    ThreatIntelQueue threatIntelQueue,
    IServiceScopeFactory scopeFactory,
    LogFileStorage storage,
    IOptions<ProcessingOptions> options,
    ILogger<LogProcessingWorker> logger) : BackgroundService
{
    private const int BatchSize = 5000;

    /// <summary>Per SQL command in the worker (big deletes and detection queries on 1-2M rows exceed the default 30 s).</summary>
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromMinutes(10);

    private ProcessingOptions Limits => options.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await RequeueUnfinishedAsync(stoppingToken);
        }
        catch (Exception) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Could not re-queue unfinished log files at start-up");
        }

        try
        {
            await foreach (var job in queue.ReadAllAsync(stoppingToken))
            {
                try
                {
                    await RunJobAsync(job, stoppingToken);
                }
                catch (Exception) when (stoppingToken.IsCancellationRequested)
                {
                    // App shutdown (SqlClient often reports it as SqlException, not OperationCanceledException):
                    // leave the status as it is, the file is resumed at the next start.
                    break;
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "{Kind} of log file {Id} failed", job.Kind, job.LogFileId);
                    await TryMarkFailedAsync(job.LogFileId, UserMessage(job.Kind, ex),
                        removeEvents: ex is LogLimitExceededException);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    private Task RunJobAsync(ProcessingJob job, CancellationToken ct) => job.Kind switch
    {
        ProcessingJobKind.Parse => ProcessAsync(job.LogFileId, ct),
        ProcessingJobKind.Detect => AnalyzeAsync(job.LogFileId, Stopwatch.StartNew(), parseMs: null, ct),
        ProcessingJobKind.Delete => DeleteAsync(job.LogFileId, ct),
        _ => Task.CompletedTask
    };

    /// <summary>Text shown to users on the file page. Technical details (paths, SQL, accounts) stay in the server log.</summary>
    public static string UserMessage(ProcessingJobKind kind, Exception ex) => ex switch
    {
        LogLimitExceededException => ex.Message,
        InvalidDataException => "The file could not be read: it is not a valid gzip archive.",
        _ when kind == ProcessingJobKind.Delete => "Deleting the file failed. Try again; details are in the server log.",
        DbException or DbUpdateException => "Database error while processing the file. Details are in the server log.",
        _ => "Unexpected error while processing the file. Details are in the server log."
    };

    private static AppDbContext CreateDb(IServiceScope scope)
    {
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.Database.SetCommandTimeout(CommandTimeout);
        return db;
    }

    // Files left unfinished when the app stopped are picked up again on startup:
    // Pending/Processing are parsed again, Analyzing only needs detection (events are already stored),
    // Deleting continues the delete. A file that was interrupted too often is marked Failed (no crash loop).
    private async Task RequeueUnfinishedAsync(CancellationToken ct)
    {
        using var scope = scopeFactory.CreateScope();
        var db = CreateDb(scope);
        var files = await db.LogFiles
            .Where(f => f.Status == LogFileStatus.Pending || f.Status == LogFileStatus.Processing
                        || f.Status == LogFileStatus.Analyzing || f.Status == LogFileStatus.Deleting)
            .Select(f => new { f.Id, f.Status, f.ProcessingAttempts })
            .ToListAsync(ct);
        foreach (var f in files)
        {
            if (f.Status == LogFileStatus.Deleting)
                await queue.EnqueueDeleteAsync(f.Id, ct);
            else if (f.ProcessingAttempts >= Limits.MaxAttempts)
            {
                logger.LogWarning("Log file {Id} was interrupted {Attempts} times and is marked Failed", f.Id, f.ProcessingAttempts);
                await TryMarkFailedAsync(f.Id,
                    $"Processing was interrupted {f.ProcessingAttempts} times (the app stopped or crashed). " +
                    "An administrator can process the file again.", removeEvents: false);
            }
            else if (f.Status == LogFileStatus.Analyzing)
                await queue.EnqueueDetectionAsync(f.Id, ct);
            else
                await queue.EnqueueAsync(f.Id, ct);
        }
    }

    private static Task CountAttemptAsync(AppDbContext db, int id, CancellationToken ct) =>
        db.LogFiles.Where(f => f.Id == id)
            .ExecuteUpdateAsync(s => s.SetProperty(f => f.ProcessingAttempts, f => f.ProcessingAttempts + 1), ct);

    private async Task ProcessAsync(int id, CancellationToken ct)
    {
        using var scope = scopeFactory.CreateScope();
        var db = CreateDb(scope);

        var file = await db.LogFiles.AsNoTracking().FirstOrDefaultAsync(f => f.Id == id, ct);
        if (file is null || file.Status == LogFileStatus.Deleting)
            return;

        var path = storage.GetPath(file);
        if (!File.Exists(path))
        {
            await TryMarkFailedAsync(id, "Uploaded file not found on disk.", removeEvents: false);
            return;
        }
        await CountAttemptAsync(db, id, ct);

        // Remove results from an earlier (or interrupted) run, in batches.
        await LogFileCleanup.DeleteResultsAndEventsAsync(db, id, ct);
        await db.LogFiles.Where(f => f.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(f => f.Status, LogFileStatus.Processing)
            .SetProperty(f => f.TotalLines, 0)
            .SetProperty(f => f.ParsedLines, 0)
            .SetProperty(f => f.FailedLines, 0)
            .SetProperty(f => f.ErrorMessage, (string?)null), ct);

        var sw = Stopwatch.StartNew();
        int total = 0, parsed = 0, failed = 0, lineNumber = 0;
        var limits = Limits;

        // Which format? The one chosen on upload, otherwise detected from the first lines (web access log or one of
        // the firewall formats). Time stamps without a year/zone are read relative to the upload (UTC).
        var context = new LogParseContext(new DateTimeOffset(DateTime.SpecifyKind(file.UploadedAt, DateTimeKind.Utc)), TimeSpan.Zero);
        var format = LogFormatRegistry.Find(file.RequestedFormat);
        if (format is null)
        {
            var sample = await ReadSampleAsync(path, file.FileName, limits, ct);
            format = LogFormatDetector.Detect(sample, context).Format;
            logger.LogInformation("Log file {Id}: detected format {Format}", id, format?.DisplayName ?? "(none)");
        }
        var recognised = format is not null;
        var parser = new MultiFormatParser(format ?? new WebAccessLogFormat(), context, allowFallback: recognised);
        await db.LogFiles.Where(f => f.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(f => f.Source, parser.Primary.Source)
            .SetProperty(f => f.Format, recognised ? parser.Primary.DisplayName : null), ct);

        await using var fileStream = File.OpenRead(path);
        using var reader = OpenReader(fileStream, file.FileName, limits);

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

        while (await reader.ReadLineAsync(ct) is { } read)
        {
            lineNumber++;
            if (lineNumber > limits.MaxLines)
                throw new LogLimitExceededException(
                    $"The file has more than {limits.MaxLines:N0} lines (limit). Split it into smaller files.");
            var line = read.Text;
            if (!read.TooLong && string.IsNullOrWhiteSpace(line))
                continue;
            total++;

            // Over-long lines are never parsed: no web server or firewall writes 16 KB lines.
            ParsedLine? p = null;
            var outcome = read.TooLong ? ParseOutcome.Failed : parser.Parse(line, out p);
            if (outcome == ParseOutcome.Parsed && p is not null)
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
                    Cut(line, 8000),
                    (object?)Cut(p.DestinationIp, 45) ?? DBNull.Value,
                    (object?)p.SourcePort ?? DBNull.Value,
                    (object?)p.DestinationPort ?? DBNull.Value,
                    (object?)Cut(p.Transport, 16) ?? DBNull.Value,
                    (object?)p.Action?.ToString() ?? DBNull.Value,
                    (object?)Cut(p.EventType, 40) ?? DBNull.Value,
                    (object?)Cut(p.RuleName, 200) ?? DBNull.Value,
                    (object?)Cut(p.ThreatName, 300) ?? DBNull.Value,
                    (object?)Cut(p.Device, 100) ?? DBNull.Value);
            }
            else if (outcome == ParseOutcome.Skipped)
            {
                // Headers, comments and device messages without a connection: neither an event nor an error.
                total--;
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
        var formatText = recognised ? parser.Describe() : null;
        await db.LogFiles.Where(f => f.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(f => f.Format, formatText)
            .SetProperty(f => f.Status, LogFileStatus.Analyzing)
            .SetProperty(f => f.TotalLines, total)
            .SetProperty(f => f.ParsedLines, parsed)
            .SetProperty(f => f.FailedLines, failed)
            .SetProperty(f => f.ParseMilliseconds, parseMs), ct);
        logger.LogInformation(
            "Log file {Id} ({Name}): {Parsed}/{Total} lines parsed, {Failed} failed, in {Ms} ms ({Rate:N0} lines/s)",
            id, file.FileName, parsed, total, failed, parseMs,
            total / Math.Max(sw.Elapsed.TotalSeconds, 0.001));

        await AnalyzeAsync(id, sw, parseMs, ct, attemptCounted: true);
    }

    /// <summary>
    /// Detection + enrichment on the stored events of one file. Used after parsing and for "Re-run detection".
    /// Threat-intel lookups are handed to <see cref="ThreatIntelWorker"/> after the file is marked Completed,
    /// because rate-limited providers can be slow and must not block the next upload.
    /// </summary>
    private async Task AnalyzeAsync(int id, Stopwatch sw, long? parseMs, CancellationToken ct, bool attemptCounted = false)
    {
        using var scope = scopeFactory.CreateScope();
        var sp = scope.ServiceProvider;
        var db = CreateDb(scope);

        if (!await db.LogFiles.AnyAsync(f => f.Id == id && f.Status != LogFileStatus.Deleting, ct))
            return;
        if (!attemptCounted)
            await CountAttemptAsync(db, id, ct);

        await db.LogFiles.Where(f => f.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(f => f.Status, LogFileStatus.Analyzing), ct);

        // Run the detection rules on the parsed events.
        var detectSw = Stopwatch.StartNew();
        var alerts = await sp.GetRequiredService<DetectionEngine>().RunAsync(id, ct);
        detectSw.Stop();

        // Hourly totals for the dashboard chart (computed once here instead of on every dashboard load).
        await LogFileStats.RebuildHourlyAsync(db, id, ct);

        // Offline country / city lookup for the attacker IPs. Never fails the whole file.
        try
        {
            await sp.GetRequiredService<IpEnrichmentService>().EnrichAlertSourcesAsync(id, ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            logger.LogWarning(ex, "GeoIP enrichment failed for log file {Id}", id);
        }

        await db.LogFiles.Where(f => f.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(f => f.Status, LogFileStatus.Completed)
            .SetProperty(f => f.ProcessedAt, DateTime.UtcNow)
            .SetProperty(f => f.ProcessingAttempts, 0)
            .SetProperty(f => f.DetectionMilliseconds, detectSw.ElapsedMilliseconds), ct);

        sw.Stop();
        logger.LogInformation("Log file {Id} completed: {Alerts} alerts, total {Ms} ms (parse {ParseMs} ms, detection {DetectMs} ms)",
            id, alerts, sw.ElapsedMilliseconds, parseMs?.ToString() ?? "-", detectSw.ElapsedMilliseconds);

        // Reputation lookups (AbuseIPDB, GreyNoise, VirusTotal) + GreyNoise severity rule: own worker, best effort.
        await threatIntelQueue.EnqueueAsync(id, ct);
    }

    private static BoundedLineReader OpenReader(FileStream fileStream, string fileName, ProcessingOptions limits)
    {
        Stream input = fileStream;
        if (LogFileStorage.IsGzip(fileName))
        {
            // Gzip bomb protection: limit the decompressed size (absolute, and relative to the upload).
            var cap = Math.Min(limits.MaxDecompressedBytes,
                Math.Max(64L * 1024 * 1024, fileStream.Length * (long)limits.MaxCompressionRatio));
            input = new LimitedReadStream(new GZipStream(fileStream, CompressionMode.Decompress), cap,
                $"The file expands to more than {Helpers.Format.Bytes(cap)} when decompressed. " +
                "It is too large or not a normal log file (gzip bomb).");
        }
        return new BoundedLineReader(new StreamReader(input), limits.MaxLineLength);
    }

    /// <summary>The first non-empty lines of the file, for format detection.</summary>
    private static async Task<List<string>> ReadSampleAsync(string path, string fileName, ProcessingOptions limits, CancellationToken ct)
    {
        var sample = new List<string>(LogFormatDetector.SampleLines);
        await using var fileStream = File.OpenRead(path);
        using var reader = OpenReader(fileStream, fileName, limits);
        var read = 0;
        while (sample.Count < LogFormatDetector.SampleLines && read++ < LogFormatDetector.SampleLines * 20
               && await reader.ReadLineAsync(ct) is { } line)
        {
            if (!line.TooLong && !string.IsNullOrWhiteSpace(line.Text))
                sample.Add(line.Text);
        }
        return sample;
    }

    /// <summary>Deletes a file and all its data in batches (the request only marks it Deleting).</summary>
    private async Task DeleteAsync(int id, CancellationToken ct)
    {
        using var scope = scopeFactory.CreateScope();
        var db = CreateDb(scope);
        var file = await db.LogFiles.AsNoTracking().FirstOrDefaultAsync(f => f.Id == id, ct);
        if (file is null)
            return;

        var sw = Stopwatch.StartNew();
        await LogFileCleanup.DeleteFileAsync(db, id, ct);
        storage.Delete(file);
        logger.LogInformation("Log file {Id} ({Name}) deleted in {Ms} ms", id, file.FileName, sw.ElapsedMilliseconds);
    }

    private static Task UpdateProgressAsync(AppDbContext db, int id, int total, int parsed, int failed, CancellationToken ct) =>
        db.LogFiles.Where(f => f.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(f => f.TotalLines, total)
            .SetProperty(f => f.ParsedLines, parsed)
            .SetProperty(f => f.FailedLines, failed), ct);

    /// <summary>Marks a file Failed. Never throws: if the database itself is down, the error is only logged.</summary>
    private async Task TryMarkFailedAsync(int id, string message, bool removeEvents)
    {
        try
        {
            using var scope = scopeFactory.CreateScope();
            var db = CreateDb(scope);
            await db.LogFiles.Where(f => f.Id == id).ExecuteUpdateAsync(s => s
                .SetProperty(f => f.Status, LogFileStatus.Failed)
                .SetProperty(f => f.ErrorMessage, Cut(message, 2000)));
            // A file over the limits keeps no partial data (it would distort the dashboard).
            if (removeEvents)
                await LogFileCleanup.DeleteResultsAndEventsAsync(db, id, CancellationToken.None);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Could not mark log file {Id} as failed", id);
        }
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
        t.Columns.Add("DestinationIp", typeof(string));
        t.Columns.Add("SourcePort", typeof(int));
        t.Columns.Add("DestinationPort", typeof(int));
        t.Columns.Add("Transport", typeof(string));
        t.Columns.Add("Action", typeof(string));
        t.Columns.Add("EventType", typeof(string));
        t.Columns.Add("RuleName", typeof(string));
        t.Columns.Add("ThreatName", typeof(string));
        t.Columns.Add("Device", typeof(string));
        return t;
    }

    private static string? Cut(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];
}
