using LogAnalyzer.Web.Models;
using static LogAnalyzer.Web.Services.LogFormats.PositionalFormatHelpers;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>
/// Windows Defender Firewall log (pfirewall.log, W3C extended style): "#Version", "#Software", "#Time Format" and
/// "#Fields" header lines are skipped, the "#Fields" order is remembered for the rest of the file (newer Windows
/// versions add "pid"). Without a header the documented default order is used:
/// date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path [pid].
/// "-" = no value; ALLOW / DROP become events, INFO-EVENTS-LOST is skipped.
/// </summary>
public sealed class WindowsFirewallFormat : ILogFormat
{
    public string Id => "windows-firewall";
    public string DisplayName => "Windows Defender Firewall";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 100;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    internal static readonly string[] DefaultFields =
    [
        "date", "time", "action", "protocol", "src-ip", "dst-ip", "src-port", "dst-port", "size", "tcpflags", "tcpsyn",
        "tcpack", "tcpwin", "icmptype", "icmpcode", "info", "path", "pid"
    ];

    private sealed class Parser(LogParseContext fileContext) : ILineParser
    {
        private readonly LogParseContext _fileContext = fileContext;
        private Columns _columns = new(DefaultFields);
        private LogParseContext _context = fileContext;

        public ParseOutcome Parse(string line, out ParsedLine? result)
        {
            result = null;
            var l = line.Trim();
            if (l.Length == 0)
                return ParseOutcome.Failed;
            if (l[0] == '#')
                return Header(l);
            // cheap check: "2026-11-21 10:00:00 ..."
            if (l.Length < 30 || l[4] != '-' || l[7] != '-' || l[10] != ' ')
                return ParseOutcome.Failed;

            var t = l.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var c = _columns;
            if (c.Date < 0 || c.Time < 0 || c.Action < 0 || t.Length < c.Required || t.Length > c.Count + 1)
                return ParseOutcome.Failed;

            var actionWord = t[c.Action].ToUpperInvariant();
            var action = actionWord switch
            {
                // OPEN / OPEN-INBOUND / CLOSE: Windows XP / Server 2003 and ICF logs (end of an allowed connection = Allow)
                "ALLOW" or "OPEN" or "OPEN-INBOUND" or "CLOSE" => FirewallAction.Allow,
                "DROP" => FirewallAction.Drop,
                _ => (FirewallAction?)null
            };
            if (!LogTime.TryParse(t[c.Date] + " " + t[c.Time], _context, out var ts))
                return ParseOutcome.Failed;
            if (actionWord == "INFO-EVENTS-LOST")
                return ParseOutcome.Skipped;
            if (action is null)
                return ParseOutcome.Failed;

            var src = Get(t, c.Src);
            var dst = Get(t, c.Dst);
            if (!IsIp(src) || !IsIp(dst))
                return ParseOutcome.Failed;
            var proto = Transport(Get(t, c.Protocol));
            var sport = Port(Get(t, c.SrcPort));
            var dport = Port(Get(t, c.DstPort));
            var path = Get(t, c.Path);
            var flags = Get(t, c.TcpFlags);
            var icmpType = Get(t, c.IcmpType);
            var pid = Get(t, c.Pid);
            var message = $"{actionWord} {proto ?? "?"} {Endpoint(src, sport)} -> {Endpoint(dst, dport)}" +
                          (path is null ? "" : $" {path}") +
                          (flags is null ? "" : $" flags {flags}") +
                          (icmpType is null ? "" : $" icmp type {icmpType} code {Get(t, c.IcmpCode) ?? "?"}") +
                          (pid is null ? "" : $" pid {pid}");
            result = ParsedLine.Network(src, ts, action.Value, message, dst, sport, dport, proto, "traffic", null, null, null,
                Long(Get(t, c.Size)));
            return ParseOutcome.Parsed;
        }

        private ParseOutcome Header(string l)
        {
            if (l.StartsWith("#Fields:", StringComparison.OrdinalIgnoreCase))
            {
                var names = l[8..].Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(n => n.ToLowerInvariant()).ToArray();
                var columns = new Columns(names);
                if (columns.Date < 0 || columns.Time < 0 || columns.Action < 0 || columns.Src < 0 || columns.Dst < 0)
                    return ParseOutcome.Failed;
                _columns = columns;
                return ParseOutcome.Skipped;
            }
            if (l.StartsWith("#Time Format:", StringComparison.OrdinalIgnoreCase))
            {
                _context = _fileContext with { DefaultOffset = l.Contains("UTC", StringComparison.OrdinalIgnoreCase) ? TimeSpan.Zero : _fileContext.DefaultOffset };
                return ParseOutcome.Skipped;
            }
            if (l.StartsWith("#Version:", StringComparison.OrdinalIgnoreCase)
                || l.StartsWith("#Software:", StringComparison.OrdinalIgnoreCase)
                || l.StartsWith("#Date:", StringComparison.OrdinalIgnoreCase)
                || l.StartsWith("#Remark:", StringComparison.OrdinalIgnoreCase))
                return ParseOutcome.Skipped;
            return ParseOutcome.Failed;
        }

        private static string? Get(string[] t, int i) => i < 0 || i >= t.Length || t[i] == "-" ? null : t[i];
    }

    private sealed class Columns
    {
        public Columns(string[] names)
        {
            Count = names.Length;
            int Ix(string n) => Array.IndexOf(names, n);
            Date = Ix("date"); Time = Ix("time"); Action = Ix("action"); Protocol = Ix("protocol");
            Src = Ix("src-ip"); Dst = Ix("dst-ip"); SrcPort = Ix("src-port"); DstPort = Ix("dst-port"); Size = Ix("size");
            TcpFlags = Ix("tcpflags"); IcmpType = Ix("icmptype"); IcmpCode = Ix("icmpcode"); Path = Ix("path"); Pid = Ix("pid");
            // the last column ("pid") is missing on older Windows versions
            Required = new[] { Date, Time, Action, Src, Dst }.Max() + 1;
        }

        public int Count { get; }
        public int Required { get; }
        public int Date { get; }
        public int Time { get; }
        public int Action { get; }
        public int Protocol { get; }
        public int Src { get; }
        public int Dst { get; }
        public int SrcPort { get; }
        public int DstPort { get; }
        public int Size { get; }
        public int TcpFlags { get; }
        public int IcmpType { get; }
        public int IcmpCode { get; }
        public int Path { get; }
        public int Pid { get; }
    }
}
