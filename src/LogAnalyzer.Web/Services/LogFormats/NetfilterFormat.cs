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

    [System.Text.RegularExpressions.GeneratedRegex(
        @"^(?:(?<ok>Accepted) (?:password|publickey|keyboard-interactive/pam) for |Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?|Invalid user )(?<u>\S{1,64}) from (?<ip>[0-9A-Fa-f:.]+)(?: port (?<p>\d{1,5}))?",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex SshdLogin();

    private sealed class Parser(LogParseContext context) : ILineParser
    {
        public ParseOutcome Parse(string line, out ParsedLine? result)
        {
            result = null;
            if (line.Length < 30)
                return ParseOutcome.Failed;
            if (!line.Contains("SRC=", StringComparison.Ordinal) || !line.Contains("DST=", StringComparison.Ordinal))
                return line.Contains("sshd", StringComparison.Ordinal) ? Sshd(line, out result) : ParseOutcome.Failed;
            var env = SyslogEnvelope.Parse(line, context);
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
        /// become authentication events (failed = Deny, accepted = Allow). Other sshd lines are skipped.
        /// </summary>
        private ParseOutcome Sshd(string line, out ParsedLine? result)
        {
            result = null;
            var env = SyslogEnvelope.Parse(line, context);
            if (env.AppName is null || !env.AppName.StartsWith("sshd", StringComparison.Ordinal))
                return ParseOutcome.Failed;
            // Junos writes "sshd: SSHD_LOGIN_FAILED: ..." - that is a Juniper line, read by its own format.
            if (env.Message.StartsWith("SSHD_", StringComparison.Ordinal))
                return ParseOutcome.Failed;
            var m = SshdLogin().Match(env.Message);
            if (!m.Success || !IsIp(m.Groups["ip"].Value))
                return ParseOutcome.Skipped;
            if (env.Timestamp is not { } ts)
                return ParseOutcome.Failed;
            var ok = m.Groups["ok"].Success;
            var user = m.Groups["u"].Value;
            int? sport = m.Groups["p"].Success ? Port(m.Groups["p"].Value) : null;
            var message = ok ? $"sshd: accepted login for {user}" : $"sshd: failed login for {user}";
            result = ParsedLine.Network(m.Groups["ip"].Value, ts, ok ? FirewallAction.Allow : FirewallAction.Deny, message,
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
