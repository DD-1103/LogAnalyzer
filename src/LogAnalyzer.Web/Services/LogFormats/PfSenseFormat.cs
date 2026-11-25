using LogAnalyzer.Web.Models;
using static LogAnalyzer.Web.Services.LogFormats.PositionalFormatHelpers;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>
/// pfSense / OPNsense "filterlog" lines (Netgate "Filter Log Format"): rule number, sub rule, anchor, tracker,
/// interface, reason, action (pass / block / reject), direction, IP version; IPv4: tos, ecn, ttl, id, offset, flags,
/// protocol id, protocol text; IPv6: class, flow label, hop limit, protocol text, protocol id; then length, source,
/// destination and for TCP / UDP the ports (TCP adds data length, flags, sequence, ...). The time comes from the
/// syslog header (BSD or RFC 5424).
/// </summary>
public sealed class PfSenseFormat : ILogFormat
{
    public string Id => "pfsense";
    public string DisplayName => "pfSense / OPNsense filterlog";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 100;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    private sealed class Parser(LogParseContext context) : ILineParser
    {
        private readonly List<string> _f = new(40);

        public ParseOutcome Parse(string line, out ParsedLine? result)
        {
            result = null;
            if (line.Length < 40 || !line.Contains("filterlog", StringComparison.Ordinal))
                return ParseOutcome.Failed;
            var env = SyslogEnvelope.Parse(line, context);
            var msg = env.Message;
            if (!string.Equals(env.AppName, "filterlog", StringComparison.Ordinal))
            {
                // "... filterlog: 5,,,..." where the envelope could not split the tag
                var tag = msg.IndexOf("filterlog", StringComparison.Ordinal);
                if (!env.RecordStartsAt(tag, 2))
                    return ParseOutcome.Failed;
                var colon = msg.IndexOf(": ", tag, StringComparison.Ordinal);
                if (colon < 0)
                    return ParseOutcome.Failed;
                msg = msg[(colon + 2)..];
            }
            if (!TrySplitCsv(msg.Trim(), 0, _f) || _f.Count < 9)
                return ParseOutcome.Failed;
            var f = _f;

            var actionWord = At(f, 6)?.ToLowerInvariant();
            // Netgate documents pass, block and unkn(%u); the other words are pf actions OPNsense can log
            if (actionWord is not ("pass" or "block" or "reject" or "match" or "scrub" or "nat" or "rdr" or "binat")
                && actionWord?.StartsWith("unkn(", StringComparison.Ordinal) != true)
                return ParseOutcome.Failed;
            var version = At(f, 8);
            int lengthIdx, protoTextIdx, protoIdIdx;
            if (version == "4")
            {
                protoIdIdx = 15;
                protoTextIdx = 16;
                lengthIdx = 17;
            }
            else if (version == "6")
            {
                protoTextIdx = 12;
                protoIdIdx = 13;
                lengthIdx = 14;
            }
            else
                return ParseOutcome.Failed;

            if (f.Count < lengthIdx + 3)
                return ParseOutcome.Failed;
            var src = At(f, lengthIdx + 1);
            var dst = At(f, lengthIdx + 2);
            if (!IsIp(src) || !IsIp(dst))
                return ParseOutcome.Failed;
            if (env.Timestamp is not { } ts)
                return ParseOutcome.Failed;
            if (actionWord is not ("pass" or "block" or "reject"))
                return ParseOutcome.Skipped;

            var proto = Transport(At(f, protoTextIdx) ?? At(f, protoIdIdx));
            int? sport = null, dport = null;
            if (proto is "tcp" or "udp")
            {
                sport = Port(At(f, lengthIdx + 3));
                dport = Port(At(f, lengthIdx + 4));
            }
            var action = actionWord switch
            {
                "pass" => FirewallAction.Allow,
                "block" => FirewallAction.Deny,
                _ => FirewallAction.Reject
            };
            var rule = At(f, 3) ?? At(f, 0);
            var iface = At(f, 4);
            var direction = At(f, 7);
            var reason = At(f, 5);
            var message = $"{actionWord} {direction ?? "?"} on {iface ?? "?"}: {proto} {Endpoint(src, sport)} -> {Endpoint(dst, dport)}" +
                          $", rule {At(f, 0) ?? "?"}" + (At(f, 3) is { } tracker ? $" (tracker {tracker})" : "") +
                          (reason is null || reason == "match" ? "" : $", reason {reason}");
            result = ParsedLine.Network(src, ts, action, message, dst, sport, dport, proto, "traffic", rule, null, env.Host,
                Long(At(f, lengthIdx)));
            return ParseOutcome.Parsed;
        }
    }
}
