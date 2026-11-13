using System.Globalization;

namespace LogAnalyzer.Tools;

/// <summary>Minimal "command --name value --flag" parser.</summary>
public sealed class Args
{
    private readonly Dictionary<string, string?> _options = new(StringComparer.OrdinalIgnoreCase);

    public string Command { get; private init; } = string.Empty;

    public static Args Parse(string[] args)
    {
        var result = new Args { Command = args.Length > 0 ? args[0].ToLowerInvariant() : string.Empty };
        for (var i = 1; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--"))
                throw new ArgumentException($"Unexpected argument '{args[i]}'.");
            var name = args[i][2..];
            string? value = null;
            if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                value = args[++i];
            result._options[name] = value;
        }
        return result;
    }

    public bool Has(string name) => _options.ContainsKey(name);

    public string Required(string name) =>
        _options.TryGetValue(name, out var v) && !string.IsNullOrWhiteSpace(v)
            ? v
            : throw new ArgumentException($"--{name} is required.");

    public string? Optional(string name) => _options.GetValueOrDefault(name);

    public int Int(string name, int fallback) =>
        _options.TryGetValue(name, out var v) && v is not null
            ? int.Parse(v.Replace("_", ""), CultureInfo.InvariantCulture)
            : fallback;

    public double Double(string name, double fallback) =>
        _options.TryGetValue(name, out var v) && v is not null
            ? double.Parse(v, CultureInfo.InvariantCulture)
            : fallback;
}
