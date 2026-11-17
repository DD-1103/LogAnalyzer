using System.Threading.Channels;
using Microsoft.Extensions.Options;

namespace LogAnalyzer.Web.Services;

/// <summary>Log files whose alerts still need reputation lookups.</summary>
public sealed class ThreatIntelQueue
{
    private readonly Channel<int> _channel = Channel.CreateUnbounded<int>();

    public ValueTask EnqueueAsync(int logFileId, CancellationToken ct = default) => _channel.Writer.WriteAsync(logFileId, ct);

    public IAsyncEnumerable<int> ReadAllAsync(CancellationToken ct) => _channel.Reader.ReadAllAsync(ct);
}

/// <summary>
/// Runs the threat-intel step (AbuseIPDB, GreyNoise, VirusTotal + GreyNoise severity rule) for completed files in
/// its own background loop, so slow or rate-limited providers never hold up the parsing of the next upload.
/// Each file gets a time budget; the step is best effort and never stops the app.
/// </summary>
public sealed class ThreatIntelWorker(
    ThreatIntelQueue queue,
    IServiceScopeFactory scopeFactory,
    IOptions<ProcessingOptions> options,
    ILogger<ThreatIntelWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var id in queue.ReadAllAsync(stoppingToken))
                await RunOneAsync(id, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    private async Task RunOneAsync(int id, CancellationToken stoppingToken)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        budget.CancelAfter(TimeSpan.FromMinutes(Math.Max(1, options.Value.ThreatIntelBudgetMinutes)));
        try
        {
            using var scope = scopeFactory.CreateScope();
            var ti = await scope.ServiceProvider.GetRequiredService<ILogFileThreatIntel>().RunForLogFileAsync(id, budget.Token);
            if (ti.Lookups > 0 || ti.Downgraded > 0)
                logger.LogInformation("Threat intel for log file {Id}: {Lookups} lookups, {Downgraded} alerts lowered",
                    id, ti.Lookups, ti.Downgraded);
        }
        catch (Exception) when (stoppingToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(stoppingToken);
        }
        catch (Exception ex) when (budget.IsCancellationRequested)
        {
            logger.LogWarning(ex, "Threat intel for log file {Id} stopped after its time budget; the rest is looked up next time", id);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Threat-intel enrichment failed for log file {Id}", id);
        }
    }
}
