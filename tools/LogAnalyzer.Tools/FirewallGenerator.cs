using System.Globalization;
using System.Text;

namespace LogAnalyzer.Tools;

/// <summary>
/// "generate-firewall": synthetic, labelled firewall log for evaluating the firewall rules (same idea as "generate" for
/// web logs). All addresses are documentation ranges (outside: 198.51.100.0/24, 192.0.2.0/24, 203.0.113.0/24) or RFC 1918
/// (inside: 10.0.0.0/16); nothing comes from a real network.
/// Labels: normal, portscan, sweep, bruteforce, flood, c2, intrusion, authfail (iptables has no IPS, so no intrusion).
/// Every label appears at least once in its plain form when the attack budget allows it (about 500 attack lines, i.e.
/// 17,000 lines at the default ratio); a warning names the labels that did not fit. About one in five further campaigns
/// is evasive (below the rule's rate, C2 on port 443). Benign but suspicious-looking: an authorised vulnerability scanner
/// probes servers port by port (0.5% of the lines, label normal: a deliberate FALSE POSITIVE of the port-scan rule), a
/// monitoring host pings 40 servers per round (1%; allowed, so the sweep rule must stay quiet) and some users mistype a
/// password (below the threshold).
/// The same seed, size, ratio and format give a byte-identical file (line ends are always LF).
/// </summary>
public static class FirewallGenerator
{
    public static readonly string[] Formats = ["fortigate", "paloalto", "cisco-asa", "iptables", "cef"];

    public static int Run(Args a)
    {
        var output = a.Required("out");
        var lines = a.Int("lines", 100_000);
        var seed = a.Int("seed", 42);
        var format = (a.Optional("format") ?? "fortigate").ToLowerInvariant();
        if (!Formats.Contains(format))
            throw new ArgumentException($"--format must be one of: {string.Join(", ", Formats)}.");
        var ratio = double.Parse(a.Optional("attack-ratio") ?? "0.03", CultureInfo.InvariantCulture);
        if (lines < 1000 || ratio is <= 0 or >= 0.5)
            throw new ArgumentException("--lines must be at least 1000 and --attack-ratio between 0 and 0.5.");
        var labels = a.Optional("labels") ?? Path.ChangeExtension(output, null) + ".labels.csv";

        var scenario = new FirewallScenario(seed, ratio, hasIps: format != "iptables");
        var events = scenario.Build(lines);
        var counts = Write(events, format, output, labels);
        Console.WriteLine($"Wrote {events.Count:N0} {format} lines to {output}");
        Console.WriteLine($"Labels: {labels}");
        foreach (var (label, count) in counts.OrderByDescending(kv => kv.Value))
            Console.WriteLine($"  {label,-12} {count,10:N0}  ({100.0 * count / events.Count:0.00}%)");
        if (scenario.MissingLabels.Count > 0)
            Console.WriteLine($"Warning: the attack budget ({lines * ratio:N0} lines) is too small for: {string.Join(", ", scenario.MissingLabels)}. " +
                              "Use more --lines or a higher --attack-ratio.");
        return 0;
    }

    private static Dictionary<string, int> Write(List<FwEvent> events, string format, string logPath, string labelsPath)
    {
        var counts = new Dictionary<string, int>();
        using var log = new StreamWriter(logPath, false, new UTF8Encoding(false), 1 << 16);
        using var lab = new StreamWriter(labelsPath, false, new UTF8Encoding(false), 1 << 16);
        log.NewLine = lab.NewLine = "\n"; // the same bytes on Windows and Linux
        lab.WriteLine("line,label");
        var n = 0;
        foreach (var e in events)
        {
            n++;
            log.WriteLine(format switch
            {
                "paloalto" => PaloAlto(e, n),
                "cisco-asa" => CiscoAsa(e, n),
                "iptables" => Iptables(e),
                "cef" => Cef(e),
                _ => FortiGate(e, n)
            });
            lab.Write(n.ToString(CultureInfo.InvariantCulture));
            lab.Write(',');
            lab.WriteLine(e.Label);
            counts[e.Label] = counts.GetValueOrDefault(e.Label) + 1;
        }
        return counts;
    }

    private static string Proto(FwEvent e) => e.Proto;
    private static int ProtoNumber(FwEvent e) => e.Proto switch { "udp" => 17, "icmp" => 1, _ => 6 };
    private static string Ts(DateTime t, string format) => t.ToString(format, CultureInfo.InvariantCulture);

    private static string FortiGate(FwEvent e, int n)
    {
        var date = $"date={Ts(e.Time, "yyyy-MM-dd")} time={Ts(e.Time, "HH:mm:ss")}";
        const string dev = "devname=\"fw01\" devid=\"FGT60FTK00000001\"";
        if (e.Kind == FwKind.Auth)
            return $"{date} {dev} logid=\"0100032002\" type=\"event\" subtype=\"system\" level=\"alert\" vd=\"root\" " +
                   $"logdesc=\"Admin login failed\" sn=\"0\" user=\"{e.User}\" ui=\"https({e.Src})\" method=\"https\" " +
                   $"srcip={e.Src} dstip={e.Dst} action=\"login\" status=\"failed\" reason=\"name_invalid\" msg=\"Administrator {e.User} login failed from https({e.Src}) because of invalid user name\"";
        if (e.Kind == FwKind.Threat)
            return $"{date} {dev} logid=\"0419016384\" type=\"utm\" subtype=\"ips\" eventtype=\"signature\" level=\"alert\" vd=\"root\" " +
                   $"severity=\"high\" srcip={e.Src} srcport={e.SrcPort} srcintf=\"wan1\" dstip={e.Dst} dstport={e.DstPort} dstintf=\"dmz\" " +
                   $"sessionid={1000000 + n} action=\"dropped\" proto={ProtoNumber(e)} service=\"HTTPS\" policyid=3 attack=\"{e.Threat}\" " +
                   $"attackid=12345 ref=\"http://www.fortinet.com/ids/VID12345\" msg=\"web_server: {e.Threat}\"";
        var action = e.Allowed ? "accept" : "deny";
        var policy = e.Allowed ? "policyid=5 policyname=\"Allow-Web\"" : "policyid=0 policyname=\"Implicit-Deny\"";
        return $"{date} {dev} logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" vd=\"root\" " +
               $"srcip={e.Src} srcport={e.SrcPort} srcintf=\"{(e.Inbound ? "wan1" : "internal")}\" dstip={e.Dst} dstport={e.DstPort} " +
               $"dstintf=\"{(e.Inbound ? "dmz" : "wan1")}\" sessionid={1000000 + n} proto={ProtoNumber(e)} action=\"{action}\" {policy} " +
               $"service=\"{e.Service}\" duration={(e.Allowed ? 12 : 0)} sentbyte={e.Bytes / 3} rcvdbyte={e.Bytes - e.Bytes / 3}";
    }

    private static string PaloAlto(FwEvent e, int n)
    {
        var t = Ts(e.Time, "yyyy/MM/dd HH:mm:ss");
        var zones = e.Inbound ? "untrust,trust,ethernet1/1,ethernet1/2" : "trust,untrust,ethernet1/2,ethernet1/1";
        if (e.Kind == FwKind.Auth)
            // Failed administrator / GlobalProtect logins are SYSTEM log lines with event id "auth-fail".
            return $"1,{t},012801000001,SYSTEM,auth,2561,{t},vsys1,auth-fail,,0,0,general,medium,\"failed authentication for user '{e.User}'. Reason: Invalid username/password. auth profile 'GP-Auth', vsys 'vsys1', From: {e.Src}.\",{n},0x0,0,0,0,0,,PA-3220";
        if (e.Kind == FwKind.Threat)
            return $"1,{t},012801000001,THREAT,vulnerability,2561,{t},{e.Src},{e.Dst},0.0.0.0,0.0.0.0,allow-web,,,web-browsing,vsys1,{zones},Forward,{t},{n},1,{e.SrcPort},{e.DstPort},0,0,0x2000,{Proto(e)},reset-both,\"login.php\",{e.Threat}(91234),any,critical,client-to-server,{n},0x0,US,10.0.0.0-10.255.255.255,0";
        var action = e.Allowed ? "allow" : "deny";
        var rule = e.Allowed ? "allow-web" : "deny-all";
        return $"1,{t},012801000001,TRAFFIC,{(e.Allowed ? "end" : "deny")},2561,{t},{e.Src},{e.Dst},0.0.0.0,0.0.0.0,{rule},,,{e.App},vsys1,{zones},Forward,{t},{n},1,{e.SrcPort},{e.DstPort},0,0,0x0,{Proto(e)},{action},{e.Bytes},{e.Bytes / 3},{e.Bytes - e.Bytes / 3},1,{t},0,any,0,{n},0x0,US,10.0.0.0-10.255.255.255,0,1,0,policy-deny";
    }

    private static string CiscoAsa(FwEvent e, int n)
    {
        var head = $"{Ts(e.Time, "MMM dd yyyy HH:mm:ss")} asa01 :";
        string inIf = e.Inbound ? "outside" : "inside", outIf = e.Inbound ? "inside" : "outside";
        if (e.Kind == FwKind.Auth)
            return $"{head} %ASA-6-605004: Login denied from {e.Src}/{e.SrcPort} to outside:{e.Dst}/ssh for user \"{e.User}\"";
        if (e.Kind == FwKind.Threat)
        {
            // The ASA itself only has a short list of packet signatures (messages 4000nn), no web attack names.
            var (id, sig, name) = AsaSignatures[Array.IndexOf(FirewallScenario.ThreatNames, e.Threat) % AsaSignatures.Length];
            return $"{head} %ASA-4-{id}: IPS:{sig} {name} from {e.Src} to {e.Dst} on interface outside";
        }
        if (!e.Allowed)
            return e.Proto == "icmp"
                ? $"{head} %ASA-3-313001: Denied ICMP type=8, code=0 from {e.Src} on interface {inIf}"
                : $"{head} %ASA-4-106023: Deny {Proto(e)} src {inIf}:{e.Src}/{e.SrcPort} dst {outIf}:{e.Dst}/{e.DstPort} by access-group \"{inIf.ToUpperInvariant()}_IN\" [0x0, 0x0]";
        if (e.Proto == "icmp")
            return $"{head} %ASA-6-302020: Built {(e.Inbound ? "inbound" : "outbound")} ICMP connection for faddr {(e.Inbound ? e.Src : e.Dst)}/0 gaddr {(e.Inbound ? e.Dst : e.Src)}/0 laddr {(e.Inbound ? e.Dst : e.Src)}/0 type 8 code 0";
        // "for" names the outside (lower security) end and "to" the inside end, also for outbound connections.
        var (message, p) = e.Proto == "udp" ? ("302015", "UDP") : ("302013", "TCP");
        string source = $"{e.Src}/{e.SrcPort}", destination = $"{e.Dst}/{e.DstPort}";
        var (outside, inside) = e.Inbound ? (source, destination) : (destination, source);
        return $"{head} %ASA-6-{message}: Built {(e.Inbound ? "inbound" : "outbound")} {p} connection {n} for outside:{outside} ({outside}) to inside:{inside} ({inside})";
    }

    private static readonly (string Id, int Signature, string Name)[] AsaSignatures =
    [
        ("400013", 2003, "ICMP redirect"), ("400026", 3040, "TCP NULL flags"), ("400027", 3041, "TCP SYN+FIN flags"),
        ("400028", 3042, "TCP FIN only flags"), ("400032", 4051, "UDP Snork attack")
    ];

    private static string Iptables(FwEvent e)
    {
        var bsd = $"{Ts(e.Time, "MMM")} {e.Time.Day,2} {Ts(e.Time, "HH:mm:ss")}";
        // kernel uptime: the gateway booted an hour before the log starts
        var uptime = (e.Time - FirewallScenario.Start).TotalSeconds + 3600;
        var head = $"{bsd} gw01 kernel: [{uptime.ToString("0.000000", CultureInfo.InvariantCulture)}]";
        if (e.Kind == FwKind.Auth)
            return $"{bsd} gw01 sshd[{2000 + e.SrcPort % 20000}]: Failed password for {(e.User == "root" ? "" : "invalid user ")}{e.User} from {e.Src} port {e.SrcPort} ssh2";
        if (e.Kind == FwKind.Threat)
            throw new InvalidOperationException("netfilter has no IPS: the scenario for iptables must not contain threat events.");
        var prefix = e.Allowed ? "[UFW ALLOW]" : "[UFW BLOCK]";
        var ports = e.Proto switch
        {
            "icmp" => "TYPE=8 CODE=0 ID=1 SEQ=1",
            "udp" => $"SPT={e.SrcPort} DPT={e.DstPort} LEN=40",
            _ => $"SPT={e.SrcPort} DPT={e.DstPort} WINDOW=64240 RES=0x00 SYN URGP=0"
        };
        return $"{head} {prefix} IN={(e.Inbound ? "eth0" : "eth1")} OUT={(e.Inbound ? "eth1" : "eth0")} SRC={e.Src} DST={e.Dst} LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=54321 DF PROTO={e.Proto.ToUpperInvariant()} {ports}";
    }

    private static string Cef(FwEvent e)
    {
        var rt = new DateTimeOffset(e.Time, TimeSpan.Zero).ToUnixTimeMilliseconds();
        if (e.Kind == FwKind.Auth)
            return $"CEF:0|ExampleVendor|ExampleFirewall|1.0|auth-fail|Administrator login failed|7|rt={rt} src={e.Src} dst={e.Dst} suser={e.User} act=deny cat=auth dvchost=fw01 outcome=failure";
        if (e.Kind == FwKind.Threat)
            return $"CEF:0|ExampleVendor|ExampleFirewall|1.0|ips-{e.DstPort}|{e.Threat}|9|rt={rt} src={e.Src} spt={e.SrcPort} dst={e.Dst} dpt={e.DstPort} proto={e.Proto.ToUpperInvariant()} act=drop cat=threat cs1Label=Rule cs1=ips-default dvchost=fw01";
        var (spt, dpt) = e.Proto == "icmp" ? ("", "") : ($" spt={e.SrcPort}", $" dpt={e.DstPort}");
        return $"CEF:0|ExampleVendor|ExampleFirewall|1.0|traffic|{(e.Allowed ? "Connection allowed" : "Connection denied")}|{(e.Allowed ? 1 : 5)}|rt={rt} src={e.Src}{spt} dst={e.Dst}{dpt} proto={e.Proto.ToUpperInvariant()} act={(e.Allowed ? "allow" : "deny")} cat=traffic cs1Label=Rule cs1={(e.Allowed ? "allow-web" : "deny-all")} dvchost=fw01 in={e.Bytes}";
    }
}

internal enum FwKind { Traffic, Threat, Auth }

internal sealed record FwEvent(DateTime Time, string Label, FwKind Kind, string Src, int SrcPort, string Dst, int DstPort, string Proto,
    bool Allowed, bool Inbound, string Service = "HTTPS", string App = "ssl", long Bytes = 0, string? Threat = null, string? User = null);

/// <summary>
/// Builds exactly the requested number of events, sorted by time (stable). Deterministic for a given seed.
/// A campaign is created at offset zero and then moved to a random start at which all of it fits into the 24 hours, and
/// it is only added when it fits the attack budget: no campaign is ever cut, so a label always means a complete attack.
/// </summary>
internal sealed class FirewallScenario
{
    internal static readonly DateTime Start = new(2026, 11, 2, 8, 0, 0, DateTimeKind.Utc);
    private static readonly TimeSpan Span = TimeSpan.FromHours(24);

    /// <summary>Hosts the monitoring server pings per round, and the share of all lines its pings may take.</summary>
    private const int MonitoredHosts = 40;
    private const double MonitoringShare = 0.01;
    private const int MaxMonitoringRounds = 288; // every 5 minutes

    /// <summary>Ports the authorised vulnerability scanner probes per server, and the share of all lines it may take.</summary>
    private const int ScannedPorts = 60;
    private const double ScannerShare = 0.005;
    private const int MaxScannerRounds = 48; // one server every half hour

    private const string WebServer = "10.0.1.10";
    private const string VpnGateway = "198.51.100.1";

    private static readonly (int Port, string Proto, string Service, string App)[] Outbound =
    [
        (443, "tcp", "HTTPS", "ssl"), (443, "tcp", "HTTPS", "ssl"), (443, "tcp", "HTTPS", "ssl"), (80, "tcp", "HTTP", "web-browsing"),
        (53, "udp", "DNS", "dns"), (123, "udp", "NTP", "ntp"), (993, "tcp", "IMAPS", "imap"), (587, "tcp", "SMTP", "smtp")
    ];

    internal static readonly string[] ThreatNames =
    [
        "HTTP.URI.SQL.Injection", "Apache.Log4j.Error.Log.Remote.Code.Execution", "PHPUnit.Eval-stdin.PHP.Remote.Code.Execution",
        "Bash.Function.Definitions.Remote.Code.Execution", "WordPress.xmlrpc.php.Brute.Force.Login"
    ];

    /// <summary>In the order of their size, so a small budget still covers as many labels as possible.</summary>
    private enum Campaign { Intrusion, AuthFailures, Beacon, Sweep, BruteForce, PortScan, Flood }

    private readonly Random _rnd;
    private readonly double _attackRatio;
    private readonly bool _hasIps;
    private readonly int[] _attackers;
    private int _nextAttacker;

    public FirewallScenario(int seed, double attackRatio, bool hasIps)
    {
        _rnd = new Random(seed);
        _attackRatio = attackRatio;
        _hasIps = hasIps;
        _attackers = Enumerable.Range(1, 254).ToArray();
        _rnd.Shuffle(_attackers);
    }

    /// <summary>Labels whose plain campaign did not fit the attack budget.</summary>
    public List<string> MissingLabels { get; } = [];

    private string Inside() => $"10.0.{_rnd.Next(2, 20)}.{_rnd.Next(10, 250)}";
    private string Outside() => _rnd.Next(2) == 0 ? $"198.51.100.{_rnd.Next(2, 255)}" : $"192.0.2.{_rnd.Next(1, 255)}";

    /// <summary>Each campaign gets its own address until all 254 are used (then they are reused in the same order).</summary>
    private string Attacker() => $"203.0.113.{_attackers[_nextAttacker++ % _attackers.Length]}";
    private int Ephemeral() => _rnd.Next(32768, 61000);
    private DateTime RandomStart(TimeSpan duration) => Start + TimeSpan.FromTicks((long)(_rnd.NextDouble() * (Span - duration).Ticks));

    public List<FwEvent> Build(int lines)
    {
        var events = new List<FwEvent>(lines);
        var budget = (int)(lines * _attackRatio);

        // 1. one plain, compact campaign per label
        foreach (var kind in Enum.GetValues<Campaign>())
        {
            if (kind == Campaign.Intrusion && !_hasIps)
                continue;
            var plain = Create(kind, compact: true, evasive: false);
            if (events.Count + plain.Count <= budget)
                events.AddRange(plain);
            else
                MissingLabels.Add(plain[0].Label);
        }

        // 2. random campaigns of random size until nothing fits any more
        for (var misses = 0; misses < 20;)
        {
            var campaign = Create(Roll(), compact: false, evasive: _rnd.Next(5) == 0);
            if (events.Count + campaign.Count <= budget)
            {
                events.AddRange(campaign);
                misses = 0;
            }
            else
                misses++;
        }

        // 3. benign monitoring host: pings 40 servers per round, at most every 5 minutes (looks like a sweep)
        var rounds = Math.Clamp((int)(lines * MonitoringShare / MonitoredHosts), 1, MaxMonitoringRounds);
        for (var r = 0; r < rounds; r++)
            for (var h = 0; h < MonitoredHosts; h++)
                events.Add(new FwEvent(Start + Span * ((r + 0.5) / rounds) + TimeSpan.FromMilliseconds(h * 50), "normal", FwKind.Traffic,
                    "10.0.0.250", 0, $"10.0.5.{10 + h}", 0, "icmp", true, false, "PING", "ping", 84));

        // 3b. authorised vulnerability scanner: 60 ports of one server per round, only the service ports are open. It
        // looks exactly like an attack, but the security team runs it, so the label is normal (allow-listing would fix it).
        var scans = Math.Clamp((int)(lines * ScannerShare / ScannedPorts), 1, MaxScannerRounds);
        for (var r = 0; r < scans; r++)
            for (var p = 0; p < ScannedPorts; p++)
            {
                var port = 20 + p * 8; // 20, 28, ... 492
                events.Add(new FwEvent(Start + Span * ((r + 0.25) / scans) + TimeSpan.FromMilliseconds(p * 200), "normal", FwKind.Traffic,
                    "10.0.0.251", 40000 + p, $"10.0.1.{2 + r % 58}", port, "tcp", port == 80, false, "tcp/" + port, "incomplete", 0));
            }

        // 4. users who mistype their password one to three times
        for (var burst = 0; burst < Math.Max(1, lines / 5000); burst++)
        {
            var src = Outside();
            var user = new[] { "jdoe", "asmith", "ops" }[_rnd.Next(3)];
            var t = RandomStart(TimeSpan.FromMinutes(2));
            for (int i = 0, n = _rnd.Next(1, 4); i < n; i++)
            {
                events.Add(new FwEvent(t, "normal", FwKind.Auth, src, Ephemeral(), VpnGateway, 443, "tcp", false, true, User: user));
                t = t.AddSeconds(_rnd.Next(5, 20));
            }
        }

        // 5. normal traffic fills the rest
        while (events.Count < lines)
        {
            var roll = _rnd.Next(100);
            var t = RandomStart(TimeSpan.Zero);
            if (roll < 70)
            {
                var o = Outbound[_rnd.Next(Outbound.Length)];
                events.Add(new FwEvent(t, "normal", FwKind.Traffic, Inside(), Ephemeral(), Outside(), o.Port, o.Proto, true, false,
                    o.Service, o.App, _rnd.Next(400, 250_000)));
            }
            else if (roll < 92)
                events.Add(new FwEvent(t, "normal", FwKind.Traffic, Outside(), Ephemeral(), WebServer, 443, "tcp", true, true,
                    "HTTPS", "ssl", _rnd.Next(800, 90_000)));
            else
            {
                // Internet background noise: single blocked probes from random hosts (not an attack on their own).
                var port = new[] { 23, 445, 3389, 8080, 22, 5900, 1433 }[_rnd.Next(7)];
                events.Add(new FwEvent(t, "normal", FwKind.Traffic, Outside(), Ephemeral(), $"10.0.1.{_rnd.Next(2, 60)}", port, "tcp",
                    false, true, "tcp/" + port, "incomplete", 0));
            }
        }

        return events.OrderBy(e => e.Time).ToList(); // stable, List.Sort is not
    }

    private Campaign Roll()
    {
        while (true)
        {
            var kind = _rnd.Next(100) switch
            {
                < 22 => Campaign.PortScan,
                < 36 => Campaign.Sweep,
                < 54 => Campaign.BruteForce,
                < 66 => Campaign.Flood,
                < 76 => Campaign.Beacon,
                < 88 => Campaign.Intrusion,
                _ => Campaign.AuthFailures
            };
            if (kind != Campaign.Intrusion || _hasIps)
                return kind;
        }
    }

    /// <summary>A complete campaign at a random time of the day. Evasive = too slow for the rule's window (C2: port 443).</summary>
    private List<FwEvent> Create(Campaign kind, bool compact, bool evasive)
    {
        var list = kind switch
        {
            Campaign.PortScan => PortScan(compact, evasive),
            Campaign.Sweep => Sweep(compact, evasive),
            Campaign.BruteForce => BruteForce(compact, evasive),
            Campaign.Flood => Flood(compact, evasive),
            Campaign.Beacon => Beacon(compact, evasive),
            Campaign.Intrusion => Intrusion(compact),
            _ => AuthFailures(compact, evasive)
        };
        var shift = RandomStart(list[^1].Time - Start) - Start;
        return list.ConvertAll(e => e with { Time = e.Time + shift });
    }

    /// <summary>The number of events is drawn once per campaign.</summary>
    private int Size(bool compact, int min, int compactMax, int max) => _rnd.Next(min, (compact ? compactMax : max) + 1);

    private List<FwEvent> PortScan(bool compact, bool slow)
    {
        var list = new List<FwEvent>();
        var src = Attacker();
        var dst = $"10.0.1.{_rnd.Next(2, 60)}";
        var t = Start;
        var ports = Enumerable.Range(1, 1024).ToArray();
        _rnd.Shuffle(ports);
        foreach (var p in ports.Take(Size(compact, 60, 100, 300)))
        {
            t = t.AddMilliseconds(slow ? _rnd.Next(8000, 15000) : _rnd.Next(20, 200));
            list.Add(new FwEvent(t, "portscan", FwKind.Traffic, src, Ephemeral(), dst, p, "tcp", p is 443, true, "tcp/" + p, "incomplete", 0));
        }
        return list;
    }

    private List<FwEvent> Sweep(bool compact, bool slow)
    {
        var list = new List<FwEvent>();
        var src = Attacker();
        var port = _rnd.Next(2) == 0 ? 445 : 3389;
        var t = Start;
        for (int h = 0, hosts = Size(compact, 40, 60, 120); h < hosts; h++)
        {
            t = t.AddMilliseconds(slow ? _rnd.Next(20_000, 40_000) : _rnd.Next(100, 1500));
            list.Add(new FwEvent(t, "sweep", FwKind.Traffic, src, Ephemeral(), $"10.0.3.{h + 2}", port, "tcp", false, true, "tcp/" + port, "incomplete", 0));
        }
        return list;
    }

    private List<FwEvent> BruteForce(bool compact, bool slow)
    {
        var list = new List<FwEvent>();
        var src = Attacker();
        var (port, svc) = _rnd.Next(2) == 0 ? (22, "SSH") : (3389, "RDP");
        var t = Start;
        for (int i = 0, n = Size(compact, 40, 70, 160); i < n; i++)
        {
            t = t.AddMilliseconds(slow ? _rnd.Next(40_000, 90_000) : _rnd.Next(800, 4000));
            list.Add(new FwEvent(t, "bruteforce", FwKind.Traffic, src, Ephemeral(), "10.0.1.20", port, "tcp", true, true, svc,
                svc.ToLowerInvariant(), _rnd.Next(2000, 6000)));
        }
        return list;
    }

    private List<FwEvent> Flood(bool compact, bool slow)
    {
        var list = new List<FwEvent>();
        var src = Attacker();
        var t = Start;
        for (int i = 0, n = Size(compact, 150, 200, 400); i < n; i++)
        {
            t = t.AddMilliseconds(slow ? _rnd.Next(650, 1200) : _rnd.Next(10, 150));
            list.Add(new FwEvent(t, "flood", FwKind.Traffic, src, Ephemeral(), $"10.0.1.{_rnd.Next(2, 6)}", 53, "udp", false, true, "DNS", "dns", 0));
        }
        return list;
    }

    private List<FwEvent> Beacon(bool compact, bool hidden)
    {
        var list = new List<FwEvent>();
        var src = Inside();
        var c2 = Attacker();
        var port = hidden ? 443 : new[] { 4444, 1337, 6667, 31337 }[_rnd.Next(4)];
        var t = Start;
        for (int i = 0, n = Size(compact, 10, 20, 40); i < n; i++)
        {
            t = t.AddSeconds(60 + _rnd.Next(-5, 6));
            list.Add(new FwEvent(t, "c2", FwKind.Traffic, src, Ephemeral(), c2, port, "tcp", true, false, hidden ? "HTTPS" : "tcp/" + port,
                hidden ? "ssl" : "unknown-tcp", _rnd.Next(200, 900)));
        }
        return list;
    }

    private List<FwEvent> Intrusion(bool compact)
    {
        var list = new List<FwEvent>();
        var src = Attacker();
        var t = Start;
        for (int i = 0, n = Size(compact, 4, 8, 8); i < n; i++)
        {
            t = t.AddSeconds(_rnd.Next(1, 20));
            list.Add(new FwEvent(t, "intrusion", FwKind.Threat, src, Ephemeral(), WebServer, 443, "tcp", false, true,
                Threat: ThreatNames[_rnd.Next(ThreatNames.Length)]));
        }
        return list;
    }

    private List<FwEvent> AuthFailures(bool compact, bool slow)
    {
        var list = new List<FwEvent>();
        var src = Attacker();
        var t = Start;
        var users = new[] { "admin", "root", "vpnuser", "test", "support" };
        for (int i = 0, n = Size(compact, 6, 12, 25); i < n; i++)
        {
            t = t.AddSeconds(slow ? _rnd.Next(90, 180) : _rnd.Next(3, 25));
            list.Add(new FwEvent(t, "authfail", FwKind.Auth, src, Ephemeral(), VpnGateway, 443, "tcp", false, true, User: users[_rnd.Next(users.Length)]));
        }
        return list;
    }
}
