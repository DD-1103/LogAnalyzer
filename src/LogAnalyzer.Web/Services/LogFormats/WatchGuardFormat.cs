using LogAnalyzer.Web.Models;
using static LogAnalyzer.Web.Services.LogFormats.PositionalFormatHelpers;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>
/// WatchGuard Firebox / Fireware OS syslog ("Fireware Log Catalog"): <c>firewall: msg_id="3000-0148" Deny 0-External
/// 1-Trusted 60 tcp 20 64 203.0.113.5 10.0.0.5 51234 22 offset 10 S 123456 win 64240 (Unhandled External Packet-00)</c>.
/// Traffic lines are positional: action, source / destination interface, [packet length], protocol, [header length,
/// TTL], source, destination, [ports], extra fields, then the policy in parentheses. A <c>signature_name="..."</c>
/// makes it an IPS event; "Authentication of ... user [...] from IP was rejected / accepted" (1100-0004 / 1100-0005) and
/// "Management user admin from IP logged in / log in attempt was rejected" (3E00-xxxx) are authentication events;
/// the attack alarms (3000-0152 ...: "PORT scan attack against A from B detected.") are threat events.
/// Other Fireware messages (msg_id present) are skipped. Checked against the Fireware v12.7 Log Catalog.
/// </summary>
public sealed partial class WatchGuardFormat : ILogFormat
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

    // The result sshd-style at the end: " from 203.0.113.9 was rejected", " logged in", " log in attempt was rejected". The
    // last match counts, the user name in front of it is attacker-controlled.
    [System.Text.RegularExpressions.GeneratedRegex(
        @" from (?<ip>[0-9A-Fa-f:.]{2,45}) (?<r>was accepted|was rejected|logged in|log ?in attempt was rejected|login attempt was rejected|rejected)",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex LoginResult();

    // "SYN flood attack against D from S detected.", "IPv4 source route attack from S detected.", "DDOS from client S detected.",
    // "IP spoofing: Traffic detected from S to D."
    [System.Text.RegularExpressions.GeneratedRegex(
        @"^(?<name>[A-Za-z0-9 ]{2,40}?) ?(?:attack |: ?Traffic detected |)(?:against (?:server )?(?<d>[0-9A-Fa-f:.]{2,45}) )?(?:from (?:client )?(?<s>[0-9A-Fa-f:.]{2,45}) )?(?:to (?<d2>[0-9A-Fa-f:.]{2,45}))?(?: ?detected|\.)",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex AttackAlarm();

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
            if (!env.RecordStartsAt(m, 3))
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

            // The first word decides, not text further on (an application name or URL may say "Authentication of").
            var t = Tokens(body);
            var word = t.Length == 0 ? "" : t[0];
            var action = Action(word);
            if (action == FirewallAction.Unknown)
            {
                if (LoginResult().IsMatch(body))
                    return Auth(body, msgId, ts, device, out result);
                return msgId.StartsWith("3000-", StringComparison.Ordinal) ? Alarm(body, msgId, ts, device, out result) : ParseOutcome.Skipped;
            }
            if (t.Length < 5)
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
            var m = LoginResult().Matches(body).LastOrDefault(x => IsIp(x.Groups["ip"].Value));
            if (m is null)
                return ParseOutcome.Skipped;
            var ip = m.Groups["ip"].Value;
            var action = m.Groups["r"].Value.Contains("rejected", StringComparison.Ordinal) ? FirewallAction.Deny : FirewallAction.Allow;
            result = ParsedLine.Network(ip, ts, action, Short($"{body} [msg_id {msgId}]"), null, null, null, null, "auth", null, null, device);
            return ParseOutcome.Parsed;
        }

        private static ParseOutcome Alarm(string body, string msgId, DateTimeOffset ts, string? device, out ParsedLine? result)
        {
            result = null;
            var m = AttackAlarm().Match(body);
            var src = m.Success && IsIp(m.Groups["s"].Value) ? m.Groups["s"].Value : null;
            var dstText = m.Groups["d"].Success ? m.Groups["d"].Value : m.Groups["d2"].Value.TrimEnd('.');
            var dst = IsIp(dstText) ? dstText : null;
            if (src is null && dst is null)
                return ParseOutcome.Skipped;
            var action = body.Contains("dropped since", StringComparison.Ordinal) ? FirewallAction.Drop : FirewallAction.Alert;
            result = ParsedLine.Network(src, ts, action, Short($"{body} [msg_id {msgId}]"), dst, null, null, null, "threat", null,
                m.Groups["name"].Value, device);
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
