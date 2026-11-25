using LogAnalyzer.Web.Models;
using static LogAnalyzer.Web.Services.LogFormats.PositionalFormatHelpers;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>
/// Linux netfilter kernel log lines written by the LOG / NFLOG targets of iptables, ip6tables and nftables and by the
/// tools on top of them (UFW, firewalld, Shorewall, Ubiquiti UniFi / EdgeOS, OpenWrt): an optional uptime
/// "[12345.678901]", the rule's log prefix ("[UFW BLOCK] ", "FINAL_REJECT: ", "[WAN_IN-default-D]", "nft drop in: "),
/// then IN= OUT= MAC= SRC= DST= LEN= ... PROTO= SPT= DPT=. The action comes from the prefix (no recognisable word =
/// Unknown), the prefix is the rule name. The time comes from the syslog / journald header.
/// </summary>
public sealed partial class NetfilterFormat : ILogFormat
{
    public string Id => "netfilter";
    public string DisplayName => "Linux netfilter (iptables / UFW / firewalld / nftables)";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 100;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    // The part sshd writes itself before the user name, and after the last " from " (address, port, "ssh2[: key]").
    [System.Text.RegularExpressions.GeneratedRegex(
        @"^(?:(?<ok>Accepted) [a-z\-/]{1,40} for |Failed [a-z\-/]{1,40} for (?:invalid user )?|Invalid user )",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex SshdLoginStart();

    [System.Text.RegularExpressions.GeneratedRegex(
        @"^(?<ip>[0-9A-Fa-f:.]{2,45})(?: port (?<p>[0-9]{1,5}))?(?: ssh2(?:: .*)?)?\z",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex SshdLoginEnd();

    // rsyslog / syslog-ng: "message repeated 5 times: [ Failed password for root from 203.0.113.9 port 4444 ssh2]"
    [System.Text.RegularExpressions.GeneratedRegex(@"^message repeated (?<n>[0-9]{1,6}) times: \[ ?(?<m>.*)\]\z",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex RepeatedMessage();

    private sealed class Parser(LogParseContext context) : ILineParser
    {
        public ParseOutcome Parse(string line, out ParsedLine? result)
        {
            result = null;
            if (line.Length < 30)
                return ParseOutcome.Failed;
            var packet = line.Contains("SRC=", StringComparison.Ordinal) && line.Contains("DST=", StringComparison.Ordinal);
            if (!packet && !line.Contains("sshd", StringComparison.Ordinal))
                return ParseOutcome.Failed;
            var env = SyslogEnvelope.Parse(line, context);
            // The program decides, not the text: an sshd user may be called "IN= SRC=10.0.0.1 DST=10.0.0.2".
            if (env.AppName?.StartsWith("sshd", StringComparison.Ordinal) == true)
                return Sshd(env, out result);
            if (!packet || env.FromOtherProgram)
                return ParseOutcome.Failed;
            var msg = env.Message;

            var inIdx = FindKey(msg, "IN=");
            if (inIdx < 0)
                return ParseOutcome.Failed;
            var prefix = Prefix(msg[..inIdx]);

            string? iface = null, outIface = null, src = null, dst = null, proto = null, spt = null, dpt = null, len = null, type = null, code = null;
            foreach (var token in msg[inIdx..].Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                var eq = token.IndexOf('=');
                if (eq <= 0)
                    continue;
                var key = token[..eq];
                var value = token[(eq + 1)..];
                switch (key)
                {
                    case "IN": iface ??= value; break;
                    case "OUT": outIface ??= value; break;
                    case "SRC": src ??= value; break;
                    case "DST": dst ??= value; break;
                    case "LEN": len ??= value; break;
                    case "PROTO": proto ??= value; break;
                    case "SPT": spt ??= value; break;
                    case "DPT": dpt ??= value; break;
                    case "TYPE": type ??= value; break;
                    case "CODE": code ??= value; break;
                }
            }
            if (!IsIp(src) || !IsIp(dst))
                return ParseOutcome.Failed;
            if (env.Timestamp is not { } ts)
                return ParseOutcome.Failed;

            var transport = Transport(proto);
            var sport = transport is "tcp" or "udp" or "sctp" ? Port(spt) : null;
            var dport = transport is "tcp" or "udp" or "sctp" ? Port(dpt) : null;
            var action = ActionFromPrefix(prefix);
            var where = string.IsNullOrEmpty(iface) ? $"out {outIface}" : string.IsNullOrEmpty(outIface) ? $"in {iface}" : $"fwd {iface}->{outIface}";
            var message = $"{prefix ?? "netfilter"} {where}: {transport ?? "ip"} {Endpoint(src, sport)} -> {Endpoint(dst, dport)}" +
                          (type is null ? "" : $" (type {type}, code {code ?? "?"})");
            result = ParsedLine.Network(src, ts, action, message, dst, sport, dport, transport, "traffic", prefix, null, env.Host,
                len is null ? null : Long(len));
            return ParseOutcome.Parsed;
        }

        /// <summary>
        /// OpenSSH login lines that Linux gateways write to the same syslog as the firewall ("sshd[123]: Failed password
        /// for invalid user admin from 203.0.113.9 port 51234 ssh2", "Invalid user x from ...", "Accepted password for ...")
        /// become authentication events (failed = Deny, accepted = Allow). The user name is attacker-controlled (it may be
        /// empty or "root from 10.0.0.1 port 22"), so the LAST "from address port" is the source. A "message repeated N
        /// times" line is one event with the count in its message. Other sshd lines are skipped.
        /// </summary>
        private static ParseOutcome Sshd(SyslogEnvelope env, out ParsedLine? result)
        {
            result = null;
            // Junos writes "sshd: SSHD_LOGIN_FAILED: ..." - that is a Juniper line, read by its own format.
            if (env.Message.StartsWith("SSHD_", StringComparison.Ordinal))
                return ParseOutcome.Failed;
            var text = env.Message.TrimEnd();
            var repeated = RepeatedMessage().Match(text);
            if (repeated.Success)
                text = repeated.Groups["m"].Value.TrimEnd();
            var start = SshdLoginStart().Match(text);
            if (!start.Success)
                return ParseOutcome.Skipped;
            var rest = " " + text[start.Length..];
            var from = rest.LastIndexOf(" from ", StringComparison.Ordinal);
            var end = from < 0 ? null : SshdLoginEnd().Match(rest[(from + 6)..]);
            if (end is not { Success: true } || !IsIp(end.Groups["ip"].Value))
                return ParseOutcome.Skipped;
            if (env.Timestamp is not { } ts)
                return ParseOutcome.Failed;
            var ok = start.Groups["ok"].Success;
            var user = Short(rest[..from].Trim(), 64);
            if (user.Length == 0)
                user = "(empty user name)";
            int? sport = end.Groups["p"].Success ? Port(end.Groups["p"].Value) : null;
            var message = (ok ? $"sshd: accepted login for {user}" : $"sshd: failed login for {user}")
                          + (repeated.Success ? $" (message repeated {repeated.Groups["n"].Value} times)" : "");
            result = ParsedLine.Network(end.Groups["ip"].Value, ts, ok ? FirewallAction.Allow : FirewallAction.Deny, message,
                null, sport, 22, "tcp", "auth", "sshd", null, env.Host);
            return ParseOutcome.Parsed;
        }

        /// <summary>Index of "IN=" that starts a token (start, after a space, ':' or ']' of the prefix).</summary>
        private static int FindKey(string msg, string key)
        {
            var i = msg.IndexOf(key, StringComparison.Ordinal);
            while (i >= 0)
            {
                if (i == 0 || !(char.IsLetterOrDigit(msg[i - 1]) || msg[i - 1] == '_'))
                    return i;
                i = msg.IndexOf(key, i + 1, StringComparison.Ordinal);
            }
            return -1;
        }

        /// <summary>"[12345.678901] [UFW BLOCK] " -> "UFW BLOCK"; "FINAL_REJECT: " -> "FINAL_REJECT"; "" -> null.</summary>
        private static string? Prefix(string head)
        {
            var p = head.Trim();
            // kernel uptime "[12345.678901]"
            if (p.StartsWith('['))
            {
                var close = p.IndexOf(']');
                if (close > 1 && p[1..close].Trim().All(c => char.IsDigit(c) || c == '.'))
                    p = p[(close + 1)..].Trim();
            }
            p = p.TrimEnd(':', ' ');
            if (p.StartsWith('[') && p.EndsWith(']'))
                p = p[1..^1].Trim();
            return p.Length == 0 ? null : p.Length > 128 ? p[..128] : p;
        }

        private static FirewallAction ActionFromPrefix(string? prefix)
        {
            if (prefix is null)
                return FirewallAction.Unknown;
            var u = prefix.ToUpperInvariant();
            if (u.Contains("REJECT"))
                return FirewallAction.Reject;
            if (u.Contains("DROP"))
                return FirewallAction.Drop;
            if (u.Contains("BLOCK") || u.Contains("DENY") || u.Contains("DENIED"))
                return FirewallAction.Deny;
            if (u.Contains("ALLOW") || u.Contains("ACCEPT") || u.Contains("PASS"))
                return FirewallAction.Allow;
            // Ubiquiti UniFi / EdgeOS: "[WAN_IN-default-D]", "-R]", "-A]"
            if (u.EndsWith("-D"))
                return FirewallAction.Drop;
            if (u.EndsWith("-R"))
                return FirewallAction.Reject;
            if (u.EndsWith("-A"))
                return FirewallAction.Allow;
            return FirewallAction.Unknown;
        }
    }
}
