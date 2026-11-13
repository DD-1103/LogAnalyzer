using System.Text;
using LogAnalyzer.Web.Services;

namespace LogAnalyzer.Tools;

/// <summary>
/// Ground truth for the DVWA lab: every request from an attacker IP (the Kali VM) is an attack, everything else
/// (the browsing / traffic-generator VM) is normal. The attack type is taken from the tool's user agent;
/// tools run with a spoofed agent are labelled generically as "attack".
/// </summary>
public static class LabelByIp
{
    private static readonly (string Needle, string Label)[] ToolLabels =
    [
        ("sqlmap", "sqli"),
        ("hydra", "bruteforce"),
        ("nikto", "scanner"),
        ("gobuster", "direnum"),
        ("dirbuster", "direnum"),
        ("dirb", "direnum"),
        ("ffuf", "direnum"),
        ("fuzz faster", "direnum"),
        ("wfuzz", "direnum"),
        ("wpscan", "scanner"),
        ("nuclei", "scanner"),
        ("nmap", "scanner")
    ];

    public static int Run(Args a)
    {
        var logPath = a.Required("log");
        var output = a.Required("out");
        var attackers = a.Required("attackers").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet();
        var parser = new CombinedLogParser();

        var counts = new Dictionary<string, int>();
        using var reader = new StreamReader(logPath);
        using var writer = new StreamWriter(output, false, new UTF8Encoding(false));
        writer.WriteLine("line,label");

        string? line;
        var n = 0;
        while ((line = reader.ReadLine()) is not null)
        {
            n++;
            if (string.IsNullOrWhiteSpace(line))
                continue;
            string label;
            if (!parser.TryParse(line, out var p) || p is null)
                label = "malformed";
            else if (!attackers.Contains(p.ClientIp))
                label = "normal";
            else
            {
                var ua = p.UserAgent?.ToLowerInvariant() ?? string.Empty;
                label = ToolLabels.FirstOrDefault(t => ua.Contains(t.Needle)).Label ?? "attack";
            }
            writer.WriteLine($"{n},{label}");
            counts[label] = counts.GetValueOrDefault(label) + 1;
        }

        Console.WriteLine($"Labelled {n:N0} lines -> {output}");
        foreach (var (label, count) in counts.OrderByDescending(c => c.Value))
            Console.WriteLine($"  {label,-12} {count,10:N0}");
        if (!counts.Keys.Any(k => k is not "normal" and not "malformed"))
            Console.WriteLine("Warning: no line came from the attacker IP(s). Check --attackers.");
        return 0;
    }
}
