using System.Reflection;
using LogAnalyzer.Web.Models;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>
/// Every <see cref="ILogFormat"/> in this assembly (found by reflection, so adding a vendor = adding one class with a
/// public parameterless constructor). Ordered by specificity, most specific first.
/// </summary>
public static class LogFormatRegistry
{
    public const string AutoId = "auto";

    private static readonly Lazy<IReadOnlyList<ILogFormat>> _all = new(() =>
        typeof(ILogFormat).Assembly.GetTypes()
            .Where(t => t is { IsClass: true, IsAbstract: false } && typeof(ILogFormat).IsAssignableFrom(t)
                        && t.GetConstructor(Type.EmptyTypes) is not null)
            .Select(t => (ILogFormat)Activator.CreateInstance(t)!)
            .OrderByDescending(f => f.Specificity).ThenBy(f => f.Id, StringComparer.Ordinal)
            .ToList());

    public static IReadOnlyList<ILogFormat> All => _all.Value;

    public static ILogFormat? Find(string? id) =>
        string.IsNullOrWhiteSpace(id) ? null : All.FirstOrDefault(f => string.Equals(f.Id, id, StringComparison.OrdinalIgnoreCase));

    public static IEnumerable<ILogFormat> OfSource(LogSource source) => All.Where(f => f.Source == source);
}

public sealed record FormatDetection(ILogFormat? Format, int Parsed, int Considered)
{
    public double Ratio => Considered == 0 ? 0 : (double)Parsed / Considered;
}

/// <summary>
/// Picks the format of a file from its first lines: every format parses the sample, the one that reads the most lines
/// wins (ties: higher <see cref="ILogFormat.Specificity"/>). Skipped lines (headers, comments) do not count.
/// At least <see cref="MinRatio"/> of the sample must be readable, otherwise no format is chosen.
/// </summary>
public static class LogFormatDetector
{
    public const int SampleLines = 200;
    public const double MinRatio = 0.3;

    public static FormatDetection Detect(IReadOnlyList<string> sample, LogParseContext context, IEnumerable<ILogFormat>? formats = null)
    {
        FormatDetection best = new(null, 0, 0);
        foreach (var format in formats ?? LogFormatRegistry.All)
        {
            var parser = format.CreateParser(context);
            int parsed = 0, considered = 0;
            foreach (var line in sample)
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;
                var outcome = SafeParse(parser, line, out _);
                if (outcome == ParseOutcome.Skipped)
                    continue;
                considered++;
                if (outcome == ParseOutcome.Parsed)
                    parsed++;
            }
            var candidate = new FormatDetection(format, parsed, considered);
            if (parsed > 0 && candidate.Ratio >= MinRatio &&
                (best.Format is null || parsed > best.Parsed
                 || (parsed == best.Parsed && format.Specificity > best.Format.Specificity)))
                best = candidate;
        }
        return best;
    }

    internal static ParseOutcome SafeParse(ILineParser parser, string line, out ParsedLine? result)
    {
        try
        {
            return parser.Parse(line, out result);
        }
        catch (Exception)
        {
            // A parser bug must never stop an import: the line counts as not readable.
            result = null;
            return ParseOutcome.Failed;
        }
    }
}

/// <summary>
/// Parses a file with its detected format; a line that format cannot read is tried with the other formats of the same
/// kind (a syslog collector often mixes several firewalls in one file). The format that read the last fallback line is
/// tried first next time. <see cref="UsedFormats"/> names every format that produced events.
/// </summary>
public sealed class MultiFormatParser
{
    private readonly (ILogFormat Format, ILineParser Parser) _primary;
    private readonly List<(ILogFormat Format, ILineParser Parser)> _fallbacks;
    private readonly Dictionary<string, int> _used = new(StringComparer.Ordinal);

    public MultiFormatParser(ILogFormat primary, LogParseContext context, bool allowFallback = true)
    {
        _primary = (primary, primary.CreateParser(context));
        _fallbacks = allowFallback
            ? LogFormatRegistry.OfSource(primary.Source).Where(f => f.Id != primary.Id).Select(f => (f, f.CreateParser(context))).ToList()
            : [];
    }

    public ILogFormat Primary => _primary.Format;

    /// <summary>Events per format display name.</summary>
    public IReadOnlyDictionary<string, int> UsedFormats => _used;

    public ParseOutcome Parse(string line, out ParsedLine? result)
    {
        var outcome = LogFormatDetector.SafeParse(_primary.Parser, line, out result);
        if (outcome != ParseOutcome.Failed)
        {
            if (outcome == ParseOutcome.Parsed)
                Count(_primary.Format);
            return outcome;
        }

        for (var i = 0; i < _fallbacks.Count; i++)
        {
            var (format, parser) = _fallbacks[i];
            outcome = LogFormatDetector.SafeParse(parser, line, out result);
            if (outcome == ParseOutcome.Failed)
                continue;
            if (i > 0)
            {
                _fallbacks.RemoveAt(i);
                _fallbacks.Insert(0, (format, parser));
            }
            if (outcome == ParseOutcome.Parsed)
                Count(format);
            return outcome;
        }
        result = null;
        return ParseOutcome.Failed;
    }

    /// <summary>"Fortinet FortiGate" or "Fortinet FortiGate + Cisco ASA / FTD" (most events first), max 300 chars.</summary>
    public string Describe()
    {
        if (_used.Count == 0)
            return _primary.Format.DisplayName;
        var text = string.Join(" + ", _used.OrderByDescending(kv => kv.Value).Select(kv => kv.Key));
        return text.Length <= 300 ? text : text[..300];
    }

    private void Count(ILogFormat format) =>
        _used[format.DisplayName] = _used.GetValueOrDefault(format.DisplayName) + 1;
}
