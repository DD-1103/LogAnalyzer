using LogAnalyzer.Web.Models;
using static LogAnalyzer.Web.Services.LogFormats.PositionalFormatHelpers;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>
/// WatchGuard Firebox / Fireware OS syslog ("Fireware Log Catalog"): <c>firewall: msg_id="3000-0148" Deny 0-External
/// 1-Trusted 60 tcp 20 64 203.0.113.5 10.0.0.5 51234 22 offset 10 S 123456 win 64240 (Unhandled External Packet-00)</c>.
/// Traffic lines are positional: action, source / destination interface, [packet length], protocol, [header length,
/// TTL], source, destination, [ports], extra fields, then the policy in parentheses. A <c>signature_name="..."</c>
/// makes it an IPS event; "Authentication of ... user [...] from IP was rejected / accepted" an authentication event.
/// Other Fireware messages (msg_id present) are skipped.
/// </summary>
public sealed class WatchGuardFormat : ILogFormat
{
    public string Id => "watchguard";
    public string DisplayName => "WatchGuard Firebox";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 100;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    private static readonly HashSet<string> Protocols = new(StringComparer.OrdinalIgnoreCase)
    {
        "tcp", "udp", "icmp", "igmp", "gre", "esp", "ah", "icmpv6", "ipv6-icmp", "sctp", "ospf", "pim", "ip"
    };

    private sealed class Parser(LogParseContext context) : ILineParser
    {
        public ParseOutcome Parse(string line, out ParsedLine? result)
        {
            result = null;
            var at = line.IndexOf("msg_id=\"", StringComparison.Ordinal);
            if (at < 0)
                return ParseOutcome.Failed;
            var env = SyslogEnvelope.Parse(line, context);
            var msg = env.Message;
            var m = msg.IndexOf("msg_id=\"", StringComparison.Ordinal);
            if (m < 0)
                return ParseOutcome.Failed;
            var idEnd = msg.IndexOf('"', m + 8);
            if (idEnd < 0 || idEnd - (m + 8) is < 4 or > 12)
                return ParseOutcome.Failed;
            var msgId = msg[(m + 8)..idEnd];
            if (!msgId.Contains('-') || !msgId.All(c => char.IsAsciiHexDigit(c) || c == '-'))
                return ParseOutcome.Failed;
            if (env.Timestamp is not { } ts)
                return ParseOutcome.Failed;
            var body = msg[(idEnd + 1)..].Trim();
            var device = env.Host;

            // Authentication of Firebox user [admin@Firebox-DB] from 203.0.113.9 was rejected, password is incorrect
            if (body.Contains("Authentication of", StringComparison.OrdinalIgnoreCase) || body.Contains(" login ", StringComparison.OrdinalIgnoreCase))
                return Auth(body, msgId, ts, device, out result);

            var t = Tokens(body);
            if (t.Length < 5)
                return ParseOutcome.Skipped;
            var word = t[0];
            var action = Action(word);
            if (action == FirewallAction.Unknown)
                return ParseOutcome.Skipped;

            var p = -1;
            for (var i = 1; i < Math.Min(t.Length, 6); i++)
                if (Protocols.Contains(t[i])) { p = i; break; }
            if (p < 0)
                return ParseOutcome.Skipped;
            int si = -1, di = -1;
            for (var i = p + 1; i < Math.Min(t.Length, p + 6); i++)
            {
                if (!IsIp(t[i])) continue;
                if (si < 0) si = i;
                else { di = i; break; }
            }
            if (si < 0 || di < 0)
                return ParseOutcome.Skipped;

            var proto = Transport(t[p]);
            int? sport = null, dport = null;
            if (proto is "tcp" or "udp" or "sctp" && di + 2 < t.Length)
            {
                sport = Port(t[di + 1]);
                dport = Port(t[di + 2]);
            }
            var policy = Policy(body);
            var signature = QuotedValue(body, "signature_name");
            var isThreat = signature is not null;
            if (isThreat && action == FirewallAction.Allow)
                action = FirewallAction.Alert;
            var fromIf = p >= 3 ? t[1] : null;
            var toIf = p >= 3 ? t[2] : null;
            long? bytes = p >= 4 ? Long(t[p - 1]) : null;
            var message = $"{word} {proto} {Endpoint(t[si], sport)} -> {Endpoint(t[di], dport)}" +
                          (fromIf is null ? "" : $" ({fromIf} -> {toIf})") +
                          (signature is null ? "" : $", signature {signature}") +
                          (policy is null ? "" : $", policy {policy}") + $" [msg_id {msgId}]";
            result = ParsedLine.Network(t[si], ts, action, Short(message), t[di], sport, dport, proto, isThreat ? "threat" : "traffic",
                policy, signature, device, bytes);
            return ParseOutcome.Parsed;
        }

        private static ParseOutcome Auth(string body, string msgId, DateTimeOffset ts, string? device, out ParsedLine? result)
        {
            result = null;
            var from = body.IndexOf(" from ", StringComparison.Ordinal);
            if (from < 0)
                return ParseOutcome.Skipped;
            var rest = body[(from + 6)..];
            var space = rest.IndexOf(' ');
            var ip = (space < 0 ? rest : rest[..space]).TrimEnd(',', '.');
            if (!IsIp(ip))
                return ParseOutcome.Skipped;
            FirewallAction action;
            if (body.Contains("rejected", StringComparison.OrdinalIgnoreCase) || body.Contains("failed", StringComparison.OrdinalIgnoreCase))
                action = FirewallAction.Deny;
            else if (body.Contains("accepted", StringComparison.OrdinalIgnoreCase) || body.Contains("succeeded", StringComparison.OrdinalIgnoreCase)
                     || body.Contains("logged in", StringComparison.OrdinalIgnoreCase))
                action = FirewallAction.Allow;
            else
                return ParseOutcome.Skipped;
            result = ParsedLine.Network(ip, ts, action, Short($"{body} [msg_id {msgId}]"), null, null, null, null, "auth", null, null, device);
            return ParseOutcome.Parsed;
        }

        /// <summary>The policy in the final "(...)" of the line, e.g. "Unhandled External Packet-00".</summary>
        private static string? Policy(string body)
        {
            var b = body.TrimEnd();
            if (!b.EndsWith(')'))
                return null;
            var open = b.LastIndexOf('(');
            if (open < 0)
                return null;
            var v = b[(open + 1)..^1].Trim();
            return v.Length is 0 or > 128 ? null : v;
        }
    }
}
