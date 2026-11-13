using System.Globalization;
using System.Text;

namespace LogAnalyzer.Tools;

/// <summary>
/// Converts the HTTP dataset CSIC 2010 (Spanish National Research Council) into Combined Log Format.
/// The dataset contains raw HTTP requests (request line, headers, optional POST body) without client IPs,
/// timestamps or responses, so these are synthesised: requests from both files are shuffled together,
/// spaced one second apart and given IPs from one shared pool (an IP never reveals the label).
/// Status is always 200 and size "-". Labels: "normal" or "attack".
/// Note: CSIC has no sessions, so per-IP detectors (threshold rules, Isolation Forest) are not meaningful
/// on it; use it to evaluate the signature rules (RQ1).
/// </summary>
public static class CsicConverter
{
    private sealed record HttpRequest(string Method, string Url, string? UserAgent, string? Referrer, string? Body, string Label);

    public static int Run(Args a)
    {
        var normal = a.Required("normal");
        var anomalous = a.Required("anomalous");
        var output = a.Required("out");
        var labels = a.Optional("labels") ?? Path.ChangeExtension(output, null) + ".labels.csv";
        var bodyAsQuery = a.Has("body-as-query");
        var rng = new Random(a.Int("seed", 42));

        var requests = Read(normal, "normal").Concat(Read(anomalous, "attack")).ToList();
        if (requests.Count == 0)
            throw new ArgumentException("No requests found. Are these the CSIC 2010 .txt files?");

        // Seeded Fisher-Yates shuffle so normal and attack requests are interleaved reproducibly.
        for (var i = requests.Count - 1; i > 0; i--)
        {
            var j = rng.Next(i + 1);
            (requests[i], requests[j]) = (requests[j], requests[i]);
        }

        var ips = Enumerable.Range(0, 500).Select(_ => $"203.0.{rng.Next(0, 256)}.{rng.Next(1, 255)}").ToArray();
        var time = new DateTimeOffset(2010, 6, 1, 8, 0, 0, TimeSpan.FromHours(2));
        int withBody = 0;

        using var log = new StreamWriter(output, false, new UTF8Encoding(false));
        using var lab = new StreamWriter(labels, false, new UTF8Encoding(false));
        lab.WriteLine("line,label");

        for (var i = 0; i < requests.Count; i++)
        {
            var r = requests[i];
            var url = r.Url;
            if (bodyAsQuery && !string.IsNullOrEmpty(r.Body))
            {
                url += (url.Contains('?') ? "&" : "?") + r.Body;
                withBody++;
            }
            var stamp = time.AddSeconds(i).ToString("dd/MMM/yyyy:HH:mm:ss", CultureInfo.InvariantCulture) + " +0200";
            log.WriteLine($"{ips[rng.Next(ips.Length)]} - - [{stamp}] \"{r.Method} {Esc(url.Replace(" ", "%20"))} HTTP/1.1\" 200 - \"{Esc(r.Referrer ?? "-")}\" \"{Esc(r.UserAgent ?? "-")}\"");
            lab.WriteLine($"{i + 1},{r.Label}");
        }

        var attacks = requests.Count(r => r.Label == "attack");
        Console.WriteLine($"Wrote {requests.Count:N0} requests ({requests.Count - attacks:N0} normal, {attacks:N0} attack) to {output}");
        Console.WriteLine($"Labels: {labels}");
        Console.WriteLine(bodyAsQuery
            ? $"POST bodies appended to the URL for {withBody:N0} requests (upper-bound scenario)."
            : "POST bodies were dropped, as in a real access log (use --body-as-query for the upper-bound scenario).");
        return 0;
    }

    private static IEnumerable<HttpRequest> Read(string path, string label)
    {
        using var reader = new StreamReader(path, Encoding.Latin1); // the dataset is ISO-8859-1
        string? line;
        string? method = null, url = null, ua = null, referrer = null;
        var contentLength = 0;

        while ((line = reader.ReadLine()) is not null)
        {
            if (method is null)
            {
                // Request line: "GET http://localhost:8080/tienda1/index.jsp HTTP/1.1"
                var parts = line.Split(' ');
                if (parts.Length >= 3 && parts[^1].StartsWith("HTTP/", StringComparison.Ordinal))
                {
                    method = parts[0];
                    url = ToPath(string.Join(' ', parts[1..^1]));
                    ua = referrer = null;
                    contentLength = 0;
                }
                continue;
            }

            if (line.Length > 0)
            {
                var colon = line.IndexOf(':');
                if (colon > 0)
                {
                    var name = line[..colon].Trim();
                    var value = line[(colon + 1)..].Trim();
                    if (name.Equals("User-Agent", StringComparison.OrdinalIgnoreCase)) ua = value;
                    else if (name.Equals("Referer", StringComparison.OrdinalIgnoreCase)) referrer = value;
                    else if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)) int.TryParse(value, out contentLength);
                }
                continue;
            }

            // Blank line = end of headers. A body (one line) follows when Content-Length > 0.
            string? body = null;
            if (contentLength > 0)
            {
                while ((line = reader.ReadLine()) is not null && line.Length == 0) { }
                body = line;
            }
            yield return new HttpRequest(method, url!, ua, referrer, body, label);
            method = null;
        }
    }

    private static string ToPath(string absolute) =>
        Uri.TryCreate(absolute, UriKind.Absolute, out var u) ? u.PathAndQuery : absolute;

    private static string Esc(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");
}
