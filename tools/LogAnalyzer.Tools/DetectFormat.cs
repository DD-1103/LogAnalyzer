using LogAnalyzer.Web.Services.LogFormats;

namespace LogAnalyzer.Tools;

/// <summary>
/// "detect": which format would the app choose for a file, and how many lines can it read? Runs the same detector and
/// line-by-line fallback as the upload worker, without the database. Prints the first lines it could not read.
/// </summary>
public static class DetectFormat
{
    public static int Run(Args a)
    {
        var path = a.Required("log");
        var show = a.Int("show-failed", 5);
        var context = new LogParseContext(DateTimeOffset.UtcNow, TimeSpan.Zero);

        var sample = File.ReadLines(path).Where(l => !string.IsNullOrWhiteSpace(l)).Take(LogFormatDetector.SampleLines).ToList();
        var detection = LogFormatDetector.Detect(sample, context);
        if (detection.Format is null)
        {
            Console.WriteLine("No format recognised in the first lines.");
            return 2;
        }
        Console.WriteLine($"Detected: {detection.Format.DisplayName} ({detection.Format.Id}), {detection.Parsed}/{detection.Considered} sample lines read");

        var parser = new MultiFormatParser(detection.Format, context);
        int parsed = 0, skipped = 0, failed = 0, n = 0;
        var actions = new Dictionary<string, int>();
        foreach (var line in File.ReadLines(path))
        {
            n++;
            if (string.IsNullOrWhiteSpace(line))
                continue;
            switch (parser.Parse(line, out var p))
            {
                case ParseOutcome.Parsed:
                    parsed++;
                    var key = p!.Action?.ToString() ?? "web";
                    actions[key] = actions.GetValueOrDefault(key) + 1;
                    break;
                case ParseOutcome.Skipped:
                    skipped++;
                    break;
                default:
                    failed++;
                    if (failed <= show)
                        Console.WriteLine($"  not read, line {n}: {(line.Length > 160 ? line[..160] + "..." : line)}");
                    break;
            }
        }
        Console.WriteLine($"Parsed {parsed:N0}, skipped {skipped:N0}, failed {failed:N0}. Formats used: {parser.Describe()}");
        Console.WriteLine("Actions: " + string.Join(", ", actions.OrderByDescending(kv => kv.Value).Select(kv => $"{kv.Key} {kv.Value:N0}")));
        return failed == 0 ? 0 : 1;
    }
}
