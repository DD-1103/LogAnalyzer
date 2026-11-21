using LogAnalyzer.Web.Models;
using static LogAnalyzer.Web.Services.LogFormats.PositionalFormatHelpers;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>
/// Amazon VPC Flow Logs as space-separated text (CloudWatch Logs export or S3 delivery). Default (version 2) fields:
/// version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status.
/// A header line with the field names (S3 files, custom formats; "${field}" is accepted too) is skipped and its order is
/// used for the rest of the file. NODATA / SKIPDATA records are skipped. ACCEPT = Allow, REJECT = Reject.
/// </summary>
public sealed class AwsVpcFlowFormat : ILogFormat
{
    public string Id => "aws-vpc-flow";
    public string DisplayName => "AWS VPC Flow Logs";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 100;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    internal static readonly string[] DefaultFields =
    [
        "version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol", "packets", "bytes",
        "start", "end", "action", "log-status"
    ];

    private sealed class Parser(LogParseContext context) : ILineParser
    {
        private string[] _names = DefaultFields;
        private Dictionary<string, int> _ix = Index(DefaultFields);
        private bool _custom;

        public ParseOutcome Parse(string line, out ParsedLine? result)
        {
            result = null;
            var t = line.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (t.Length < 5 || t.Length > 64)
                return ParseOutcome.Failed;
            if (IsHeader(t))
            {
                _names = t.Select(n => n.Trim('$', '{', '}').ToLowerInvariant()).ToArray();
                _ix = Index(_names);
                _custom = true;
                return ParseOutcome.Skipped;
            }
            if (t.Length != _names.Length)
                return ParseOutcome.Failed;

            if (!_custom)
            {
                // default v2 layout: "2 123456789012 eni-..." - cheap validation before anything else
                if (t[0].Length > 2 || !t[0].All(char.IsDigit) || !(t[2].StartsWith("eni-", StringComparison.Ordinal) || t[2] == "-"))
                    return ParseOutcome.Failed;
            }

            var status = Get(t, "log-status");
            var start = Get(t, "start") ?? Get(t, "end");
            if (start is null || start.Length is < 9 or > 13 || !start.All(char.IsDigit) || !LogTime.TryParse(start, context, out var ts))
                return ParseOutcome.Failed;
            if (status is "NODATA" or "SKIPDATA")
                return ParseOutcome.Skipped;

            var src = Get(t, "srcaddr");
            var dst = Get(t, "dstaddr");
            if (!IsIp(src) || !IsIp(dst))
                return ParseOutcome.Failed;
            var actionWord = Get(t, "action");
            var action = actionWord switch
            {
                "ACCEPT" => FirewallAction.Allow,
                "REJECT" => FirewallAction.Reject,
                null => FirewallAction.Unknown,
                _ => (FirewallAction?)null
            };
            if (action is null)
                return ParseOutcome.Failed;

            var proto = Transport(Get(t, "protocol"));
            var ports = proto is "tcp" or "udp" or "sctp";
            var sport = ports ? Port(Get(t, "srcport")) : null;
            var dport = ports ? Port(Get(t, "dstport")) : null;
            var eni = Get(t, "interface-id");
            var packets = Get(t, "packets");
            var direction = Get(t, "flow-direction");
            var message = $"{actionWord ?? "-"} {proto ?? "?"} {Endpoint(src, sport)} -> {Endpoint(dst, dport)}" +
                          (direction is null ? "" : $" {direction}") +
                          (eni is null ? "" : $" on {eni}") +
                          (packets is null ? "" : $", {packets} packets") +
                          (Get(t, "bytes") is { } b ? $", {b} bytes" : "");
            result = ParsedLine.Network(src, ts, action.Value, message, dst, sport, dport, proto, "traffic", null, null,
                eni ?? Get(t, "instance-id"), Long(Get(t, "bytes")));
            return ParseOutcome.Parsed;
        }

        private string? Get(string[] t, string name) =>
            _ix.TryGetValue(name, out var i) && i < t.Length && t[i] != "-" ? t[i] : null;

        private static bool IsHeader(string[] t)
        {
            var hasSrc = false;
            var hasDst = false;
            foreach (var raw in t)
            {
                var n = raw.Trim('$', '{', '}');
                if (n.Length == 0 || !n.All(c => c is >= 'a' and <= 'z' or '-' or '_' or >= '0' and <= '9'))
                    return false;
                hasSrc |= n == "srcaddr";
                hasDst |= n == "dstaddr";
            }
            return hasSrc && hasDst;
        }

        private static Dictionary<string, int> Index(string[] names)
        {
            var d = new Dictionary<string, int>(StringComparer.Ordinal);
            for (var i = 0; i < names.Length; i++)
                d.TryAdd(names[i], i);
            return d;
        }
    }
}
