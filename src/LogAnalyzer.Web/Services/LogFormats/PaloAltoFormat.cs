using LogAnalyzer.Web.Models;
using static LogAnalyzer.Web.Services.LogFormats.PositionalFormatHelpers;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>
/// Palo Alto Networks PAN-OS syslog in the default CSV layout (PAN-OS 10 / 11 "Syslog Field Descriptions"), with or
/// without a syslog header. Field positions (0-based): 1 receive time, 2 serial, 3 type, 4 subtype, 6 generated time,
/// 7 source, 8 destination, 11 rule, 12 source user, 14 application, 16/17 zones, 22 session id, 24/25 ports,
/// 29 protocol, 30 action; TRAFFIC 31 bytes; THREAT 31 URL / file name, 32 threat name(id), 33 category,
/// 34 severity, 35 direction. GLOBALPROTECT, AUTH and SYSTEM "auth-fail" lines become authentication events when the
/// user and source address are present; every other PAN-OS log type is skipped.
/// </summary>
public sealed class PaloAltoFormat : ILogFormat
{
    public string Id => "paloalto";
    public string DisplayName => "Palo Alto Networks PAN-OS";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 100;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    private static readonly string[] KnownTypes =
    [
        "TRAFFIC", "THREAT", "SYSTEM", "CONFIG", "GLOBALPROTECT", "AUTH", "USERID", "HIPMATCH", "CORRELATION",
        "DECRYPTION", "TUNNEL", "GTP", "SCTP", "IPTAG", "WILDFIRE"
    ];

    private sealed class Parser(LogParseContext context) : ILineParser
    {
        private readonly List<string> _f = new(128);

        public ParseOutcome Parse(string line, out ParsedLine? result)
        {
            result = null;
            if (line.Length < 30 || !HasKnownType(line))
                return ParseOutcome.Failed;

            var env = SyslogEnvelope.Parse(line, context);
            var msg = env.Message;
            if (!TrySplitCsv(msg, 0, _f) || _f.Count < 7)
                return ParseOutcome.Failed;

            var f = _f;
            var type = f[3].Trim();
            if (Array.IndexOf(KnownTypes, type) < 0)
                return ParseOutcome.Failed;
            // FUTURE_USE (usually "1" or empty), receive time and serial must look right
            if (f[0].Length > 0 && !f[0].All(char.IsDigit))
                return ParseOutcome.Failed;
            if (!LogTime.TryParse(f[1], context, out var received))
                return ParseOutcome.Failed;

            var ts = LogTime.TryParse(f[6], context, out var generated) ? generated : received;
            var device = env.Host ?? At(f, 2);
            var subtype = At(f, 4)?.ToLowerInvariant() ?? "";

            return type switch
            {
                "TRAFFIC" => Traffic(f, ts, device, subtype, out result),
                "THREAT" => Threat(f, ts, device, subtype, out result),
                "GLOBALPROTECT" => GlobalProtect(f, ts, device, out result),
                "AUTH" => Auth(f, ts, device, out result),
                "SYSTEM" => SystemAuth(f, ts, device, subtype, out result),
                _ => ParseOutcome.Skipped
            };
        }

        private static bool HasKnownType(string line)
        {
            foreach (var t in KnownTypes)
            {
                var i = line.IndexOf(t, StringComparison.Ordinal);
                if (i > 0 && line[i - 1] == ',' && i + t.Length < line.Length && line[i + t.Length] == ',')
                    return true;
            }
            return false;
        }

        private static ParseOutcome Traffic(List<string> f, DateTimeOffset ts, string? device, string subtype, out ParsedLine? result)
        {
            result = null;
            if (f.Count < 31)
                return ParseOutcome.Failed;
            var src = At(f, 7);
            var dst = At(f, 8);
            if (!IsIp(src) || !IsIp(dst))
                return ParseOutcome.Failed;
            var actionWord = At(f, 30);
            var action = Action(actionWord);
            var proto = Transport(At(f, 29));
            var sport = Port(At(f, 24));
            var dport = Port(At(f, 25));
            var rule = At(f, 11);
            var app = At(f, 14);
            var bytes = Long(At(f, 31));
            var message = $"traffic {subtype}: {app ?? "unknown app"} {proto} {Endpoint(src, sport)} -> {Endpoint(dst, dport)}" +
                          $" ({At(f, 16) ?? "?"} -> {At(f, 17) ?? "?"}), rule {rule ?? "?"}, action {actionWord ?? "?"}";
            result = ParsedLine.Network(src, ts, action, message, dst, sport, dport, proto, "traffic", rule, null, device, bytes);
            return ParseOutcome.Parsed;
        }

        private static ParseOutcome Threat(List<string> f, DateTimeOffset ts, string? device, string subtype, out ParsedLine? result)
        {
            result = null;
            if (f.Count < 36)
                return ParseOutcome.Failed;
            var src = At(f, 7);
            var dst = At(f, 8);
            if (!IsIp(src) || !IsIp(dst))
                return ParseOutcome.Failed;
            var actionWord = At(f, 30)?.ToLowerInvariant();
            var isUrl = subtype == "url";
            var action = actionWord switch
            {
                // URL filtering: "alert" / "continue" / "override" = the page was shown
                "alert" or "allow" or "continue" or "override" when isUrl => FirewallAction.Allow,
                "block-continue" or "block-override" => FirewallAction.Deny,
                // threat detected but let through
                "allow" or "alert" or "continue" or "override" => FirewallAction.Alert,
                _ => Action(actionWord)
            };
            var proto = Transport(At(f, 29));
            var sport = Port(At(f, 24));
            var dport = Port(At(f, 25));
            var rule = At(f, 11);
            var misc = At(f, 31);
            var threat = At(f, 32);
            var category = At(f, 33);
            var severity = At(f, 34);
            var direction = At(f, 35);
            if (category == "any")
                category = null;

            string message;
            if (isUrl)
            {
                message = $"url: {misc ?? "?"} [{category ?? "uncategorised"}] {Endpoint(src, sport)} -> {Endpoint(dst, dport)}, action {actionWord ?? "?"}";
                result = ParsedLine.Network(src, ts, action, Short(message), dst, sport, dport, proto, "url", rule, null, device);
                return ParseOutcome.Parsed;
            }

            message = $"threat {subtype}: {threat ?? "unknown"}" +
                      (severity is null ? "" : $" [{severity}]") +
                      (category is null ? "" : $" ({category})") +
                      $" {proto} {Endpoint(src, sport)} -> {Endpoint(dst, dport)}" +
                      (direction is null ? "" : $" {direction}") +
                      (misc is null ? "" : $", {misc}") +
                      $", action {actionWord ?? "?"}";
            result = ParsedLine.Network(src, ts, action, Short(message), dst, sport, dport, proto, "threat", rule, threat, device);
            return ParseOutcome.Parsed;
        }

        // GLOBALPROTECT: 8 event id, 9 stage, 10 auth method, 12 source user, 15 public IP, 17 private IP,
        // 25 reason, 26 error, 27 description, 28 status (success / failure), 33 portal / gateway
        private static ParseOutcome GlobalProtect(List<string> f, DateTimeOffset ts, string? device, out ParsedLine? result)
        {
            result = null;
            if (f.Count < 29)
                return ParseOutcome.Skipped;
            var eventId = At(f, 8)?.ToLowerInvariant() ?? "";
            var user = At(f, 12);
            var ip = At(f, 15) ?? At(f, 16);
            var status = At(f, 28)?.ToLowerInvariant();
            if (!IsIp(ip) || user is null || status is not ("success" or "failure"))
                return ParseOutcome.Skipped;

            var isAuth = eventId.Contains("auth") || eventId.Contains("login") || eventId.Contains("prelogin");
            if (status == "success" && !isAuth && !eventId.Contains("connect"))
                return ParseOutcome.Skipped;
            var action = status == "failure" ? FirewallAction.Deny : FirewallAction.Allow;
            var eventType = status == "failure" || isAuth ? "auth" : "vpn";
            var detail = At(f, 26) ?? At(f, 25) ?? At(f, 27);
            var message = $"GlobalProtect {eventId} {status} for user {user} from {ip}" + (detail is null ? "" : $": {detail}");
            result = ParsedLine.Network(ip, ts, action, Short(message), null, null, null, null, eventType, At(f, 33), null, device);
            return ParseOutcome.Parsed;
        }

        // AUTH: 8 source IP, 9 user, 12 authentication policy, 18 description, 20 event type (auth-success / auth-fail ...)
        private static ParseOutcome Auth(List<string> f, DateTimeOffset ts, string? device, out ParsedLine? result)
        {
            result = null;
            if (f.Count < 21)
                return ParseOutcome.Skipped;
            var ip = At(f, 8);
            var user = At(f, 9);
            var eventType = At(f, 20)?.ToLowerInvariant() ?? "";
            if (!IsIp(ip) || user is null)
                return ParseOutcome.Skipped;
            FirewallAction action;
            if (eventType.Contains("fail"))
                action = FirewallAction.Deny;
            else if (eventType.Contains("success"))
                action = FirewallAction.Allow;
            else
                return ParseOutcome.Skipped;
            var desc = At(f, 18);
            var message = $"authentication {eventType} for user {user} from {ip}" + (desc is null ? "" : $": {desc}");
            result = ParsedLine.Network(ip, ts, action, Short(message), null, null, null, null, "auth", At(f, 12), null, device);
            return ParseOutcome.Parsed;
        }

        // SYSTEM: 8 event id, 14 description, e.g. auth-fail "failed authentication for user 'admin'. Reason: ... From: 203.0.113.9."
        private static ParseOutcome SystemAuth(List<string> f, DateTimeOffset ts, string? device, string subtype, out ParsedLine? result)
        {
            result = null;
            var eventId = At(f, 8)?.ToLowerInvariant();
            var desc = At(f, 14);
            if (eventId != "auth-fail" || desc is null)
                return ParseOutcome.Skipped;
            var from = desc.IndexOf("From: ", StringComparison.OrdinalIgnoreCase);
            var userStart = desc.IndexOf("user '", StringComparison.OrdinalIgnoreCase);
            if (from < 0 || userStart < 0)
                return ParseOutcome.Skipped;
            var ip = desc[(from + 6)..].TrimEnd('.', ' ');
            var space = ip.IndexOf(' ');
            if (space > 0)
                ip = ip[..space].TrimEnd('.');
            var userEnd = desc.IndexOf('\'', userStart + 6);
            if (!IsIp(ip) || userEnd < 0)
                return ParseOutcome.Skipped;
            result = ParsedLine.Network(ip, ts, FirewallAction.Deny, Short($"system {subtype}: {desc}"), null, null, null, null, "auth", null, null, device);
            return ParseOutcome.Parsed;
        }
    }
}
