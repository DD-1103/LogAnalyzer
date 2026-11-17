using LogAnalyzer.Web.Data;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Services;

/// <summary>
/// Deletes the data of one log file in small batches. One huge DELETE of 1-2M wide LogEvents rows runs into the
/// command timeout and fills the transaction log; batches of a few thousand rows finish quickly, and an interrupted
/// delete simply continues where it stopped (the file keeps the status Deleting / Processing until it is done).
/// </summary>
public static class LogFileCleanup
{
    public const int EvidenceBatch = 50_000;
    public const int EventBatch = 20_000;
    public const int AlertBatch = 5_000;

    /// <summary>Removes alerts and their evidence (evidence first: it references events and alerts).</summary>
    public static async Task DeleteAlertsAsync(AppDbContext db, int logFileId, CancellationToken ct)
    {
        while (await db.Database.ExecuteSqlAsync(
                   $"DELETE TOP ({EvidenceBatch}) FROM [AlertEvidence] WHERE [AlertId] IN (SELECT [Id] FROM [Alerts] WHERE [LogFileId] = {logFileId})",
                   ct) > 0)
        {
        }
        while (await db.Database.ExecuteSqlAsync(
                   $"DELETE TOP ({AlertBatch}) FROM [Alerts] WHERE [LogFileId] = {logFileId}", ct) > 0)
        {
        }
    }

    /// <summary>Removes alerts, evidence and all parsed events of the file (the file row stays).</summary>
    public static async Task DeleteResultsAndEventsAsync(AppDbContext db, int logFileId, CancellationToken ct)
    {
        await DeleteAlertsAsync(db, logFileId, ct);
        while (await db.Database.ExecuteSqlAsync(
                   $"DELETE TOP ({EventBatch}) FROM [LogEvents] WHERE [LogFileId] = {logFileId}", ct) > 0)
        {
        }
    }

    /// <summary>Removes everything of the file, including the file row itself.</summary>
    public static async Task DeleteFileAsync(AppDbContext db, int logFileId, CancellationToken ct)
    {
        await DeleteResultsAndEventsAsync(db, logFileId, ct);
        await db.LogFiles.Where(f => f.Id == logFileId).ExecuteDeleteAsync(ct);
    }
}
