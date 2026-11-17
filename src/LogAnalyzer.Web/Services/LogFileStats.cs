using LogAnalyzer.Web.Data;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Services;

/// <summary>Pre-computed statistics of a log file for the dashboard (see <see cref="Models.LogFileHourStat"/>).</summary>
public static class LogFileStats
{
    /// <summary>Recomputes the hourly counts of one file (after parsing / re-running detection).</summary>
    public static async Task RebuildHourlyAsync(AppDbContext db, int logFileId, CancellationToken ct)
    {
        await db.Database.ExecuteSqlAsync($"DELETE FROM [LogFileHourStats] WHERE [LogFileId] = {logFileId}", ct);
        await db.Database.ExecuteSqlAsync($"""
            INSERT INTO [LogFileHourStats] ([LogFileId], [Hour], [Total], [Flagged])
            SELECT e.[LogFileId], h.[Hour], COUNT(*), COUNT(f.[LogEventId])
            FROM [LogEvents] AS e
            CROSS APPLY (SELECT DATEADD(hour, DATEDIFF(hour, CAST('2000-01-01' AS datetime2), CAST(e.[Timestamp] AS datetime2)),
                                        CAST('2000-01-01' AS datetime2)) AS [Hour]) AS h
            LEFT JOIN (SELECT DISTINCT ev.[LogEventId]
                       FROM [AlertEvidence] AS ev INNER JOIN [Alerts] AS a ON a.[Id] = ev.[AlertId]
                       WHERE a.[LogFileId] = {logFileId}) AS f ON f.[LogEventId] = e.[Id]
            WHERE e.[LogFileId] = {logFileId}
            GROUP BY e.[LogFileId], h.[Hour]
            """, ct);
    }
}
