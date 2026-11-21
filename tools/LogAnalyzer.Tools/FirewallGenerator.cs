using System.Globalization;
using System.Text;

namespace LogAnalyzer.Tools;

/// <summary>
/// "generate-firewall": synthetic, labelled firewall log for evaluating the firewall rules (same idea as "generate" for
/// web logs). All addresses are documentation ranges (outside: 198.51.100.0/24, 192.0.2.0/24, 203.0.113.0/24) or RFC 1918
/// (inside: 10.0.0.0/16); nothing comes from a real network.
/// Labels: normal, portscan, sweep, bruteforce, flood, c2, intrusion, authfail. Evasive variants (slow scan, slow
/// brute force) and a benign monitoring host that pings many hosts are included on purpose, so the results show
/// realistic misses and false positives.
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

        var events = new FirewallScenario(seed, ratio).Build(lines);
        var counts = Write(events, format, output, labels);
        Console.WriteLine($"Wrote {events.Count:N0} {format} lines to {output}");
        Console.WriteLine($"Labels: {labels}");
        foreach (var (label, count) in counts.OrderByDescending(kv => kv.Value))
            Console.WriteLine($"  {label,-12} {count,10:N0}  ({100.0 * count / events.Count:0.00}%)");
        return 0;
    }

    private static Dictionary<string, int> Write(List<FwEvent> events, string format, string logPath, string labelsPath)
    {
        var counts = new Dictionary<string, int>();
        using var log = new StreamWriter(logPath, false, new UTF8Encoding(false), 1 << 16);
        using var lab = new StreamWriter(labelsPath, false, new UTF8Encoding(false), 1 << 16);
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
            // GLOBALPROTECT logs are complex; failed portal logins appear as SYSTEM-like lines that parsers may skip.
            return $"1,{t},012801000001,SYSTEM,auth,2561,{t},,general,,0,0,general,high,\"authentication failed for user '{e.User}'. From: {e.Src}.\",{n},0x0,0,0,0,0,,PA-3220";
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
            return $"{head} %ASA-4-400013: IPS:2003 ICMP redirect from {e.Src} to {e.Dst} on interface outside";
        if (!e.Allowed)
            return e.Proto == "icmp"
                ? $"{head} %ASA-3-313001: Denied ICMP type=8, code=0 from {e.Src} on interface {inIf}"
                : $"{head} %ASA-4-106023: Deny {Proto(e)} src {inIf}:{e.Src}/{e.SrcPort} dst {outIf}:{e.Dst}/{e.DstPort} by access-group \"{inIf.ToUpperInvariant()}_IN\" [0x0, 0x0]";
        var p = e.Proto.ToUpperInvariant();
        return $"{head} %ASA-6-302013: Built {(e.Inbound ? "inbound" : "outbound")} {p} connection {n} for {inIf}:{e.Src}/{e.SrcPort} ({e.Src}/{e.SrcPort}) to {outIf}:{e.Dst}/{e.DstPort} ({e.Dst}/{e.DstPort})";
    }

    private static string Iptables(FwEvent e)
    {
        var bsd = $"{Ts(e.Time, "MMM")} {e.Time.Day,2} {Ts(e.Time, "HH:mm:ss")}";
        var head = $"{bsd} gw01 kernel: [{e.Time.TimeOfDay.TotalSeconds.ToString("0.000000", CultureInfo.InvariantCulture)}]";
        if (e.Kind == FwKind.Auth)
            return $"{bsd} gw01 sshd[2211]: Failed password for invalid user {e.User} from {e.Src} port {e.SrcPort} ssh2";
        var prefix = e.Kind == FwKind.Threat ? "[UFW BLOCK]" : e.Allowed ? "[UFW ALLOW]" : "[UFW BLOCK]";
        var ports = e.Proto == "icmp" ? "TYPE=8 CODE=0 ID=1 SEQ=1" : $"SPT={e.SrcPort} DPT={e.DstPort} WINDOW=64240 RES=0x00 SYN URGP=0";
        return $"{head} {prefix} IN={(e.Inbound ? "eth0" : "eth1")} OUT={(e.Inbound ? "eth1" : "eth0")} SRC={e.Src} DST={e.Dst} LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=54321 DF PROTO={e.Proto.ToUpperInvariant()} {ports}";
    }

    private static string Cef(FwEvent e)
    {
        var rt = new DateTimeOffset(e.Time, TimeSpan.Zero).ToUnixTimeMilliseconds();
        if (e.Kind == FwKind.Auth)
            return $"CEF:0|ExampleVendor|ExampleFirewall|1.0|auth-fail|Administrator login failed|7|rt={rt} src={e.Src} dst={e.Dst} suser={e.User} act=deny cat=auth dvchost=fw01 outcome=failure";
        if (e.Kind == FwKind.Threat)
            return $"CEF:0|ExampleVendor|ExampleFirewall|1.0|ips-{e.DstPort}|{e.Threat}|9|rt={rt} src={e.Src} spt={e.SrcPort} dst={e.Dst} dpt={e.DstPort} proto={e.Proto.ToUpperInvariant()} act=drop cat=threat cs1Label=Rule cs1=ips-default dvchost=fw01";
        return $"CEF:0|ExampleVendor|ExampleFirewall|1.0|traffic|{(e.Allowed ? "Connection allowed" : "Connection denied")}|{(e.Allowed ? 1 : 5)}|rt={rt} src={e.Src} spt={e.SrcPort} dst={e.Dst} dpt={e.DstPort} proto={e.Proto.ToUpperInvariant()} act={(e.Allowed ? "allow" : "deny")} cat=traffic cs1Label=Rule cs1={(e.Allowed ? "allow-web" : "deny-all")} dvchost=fw01 in={e.Bytes}";
    }
}

internal enum FwKind { Traffic, Threat, Auth }

internal sealed record FwEvent(DateTime Time, string Label, FwKind Kind, string Src, int SrcPort, string Dst, int DstPort, string Proto,
    bool Allowed, bool Inbound, string Service = "HTTPS", string App = "ssl", long Bytes = 0, string? Threat = null, string? User = null);

/// <summary>Builds the event list (sorted by time). Deterministic for a given seed.</summary>
internal sealed class FirewallScenario(int seed, double attackRatio)
{
    private readonly Random _rnd = new(seed);
    private static readonly DateTime Start = new(2026, 11, 2, 8, 0, 0, DateTimeKind.Utc);
    private static readonly TimeSpan Span = TimeSpan.FromHours(24);

    private static readonly (int Port, string Proto, string Service, string App)[] Outbound =
    [
        (443, "tcp", "HTTPS", "ssl"), (443, "tcp", "HTTPS", "ssl"), (443, "tcp", "HTTPS", "ssl"), (80, "tcp", "HTTP", "web-browsing"),
        (53, "udp", "DNS", "dns"), (123, "udp", "NTP", "ntp"), (993, "tcp", "IMAPS", "imap"), (587, "tcp", "SMTP", "smtp")
    ];

    private static readonly string[] ThreatNames =
    [
        "HTTP.URI.SQL.Injection", "Apache.Log4j.Error.Log.Remote.Code.Execution", "PHPUnit.Eval-stdin.PHP.Remote.Code.Execution",
        "Bash.Function.Definitions.Remote.Code.Execution", "WordPress.xmlrpc.php.Brute.Force.Login"
    ];

    private string Inside() => $"10.0.{_rnd.Next(2, 20)}.{_rnd.Next(10, 250)}";
    private string Outside() => _rnd.Next(2) == 0 ? $"198.51.100.{_rnd.Next(1, 255)}" : $"192.0.2.{_rnd.Next(1, 255)}";
    private string Attacker() => $"203.0.113.{_rnd.Next(1, 255)}";
    private int Ephemeral() => _rnd.Next(32768, 61000);
    private DateTime RandomTime() => Start + TimeSpan.FromSeconds(_rnd.NextDouble() * Span.TotalSeconds);
    private const string WebServer = "10.0.1.10";
    private const string VpnGateway = "198.51.100.1";

    public List<FwEvent> Build(int lines)
    {
        var events = new List<FwEvent>(lines + 1000);
        var attackBudget = (int)(lines * attackRatio);

        // Attack campaigns until the budget is used (each campaign is a realistic burst).
        var attackEvents = new List<FwEvent>();
        while (attackEvents.Count < attackBudget)
        {
            var roll = _rnd.Next(100);
            if (roll < 22) PortScan(attackEvents, slow: _rnd.Next(5) == 0);
            else if (roll < 36) Sweep(attackEvents);
            else if (roll < 54) BruteForce(attackEvents, slow: _rnd.Next(5) == 0);
            else if (roll < 66) Flood(attackEvents);
            else if (roll < 76) Beacon(attackEvents);
            else if (roll < 88) Intrusion(attackEvents);
            else AuthFailures(attackEvents);
        }
        events.AddRange(attackEvents);

        // Benign monitoring host: pings 40 servers every 5 minutes (looks like a sweep - a realistic false positive).
        for (var t = Start; t < Start + Span && events.Count < lines / 2; t = t.AddMinutes(5))
            for (var h = 0; h < 40; h++)
                events.Add(new FwEvent(t.AddMilliseconds(h * 50), "normal", FwKind.Traffic, "10.0.0.250", 0, $"10.0.5.{10 + h}", 0, "icmp",
                    true, false, "PING", "ping", 84));

        // Normal traffic fills the rest.
        while (events.Count < lines)
        {
            var r = _rnd.Next(100);
            var t = RandomTime();
            if (r < 70)
            {
                var o = Outbound[_rnd.Next(Outbound.Length)];
                events.Add(new FwEvent(t, "normal", FwKind.Traffic, Inside(), Ephemeral(), Outside(), o.Port, o.Proto, true, false,
                    o.Service, o.App, _rnd.Next(400, 250_000)));
            }
            else if (r < 92)
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

        events.Sort((a, b) => a.Time.CompareTo(b.Time));
        if (events.Count > lines)
            events.RemoveRange(lines, events.Count - lines);
        return events;
    }

    private void PortScan(List<FwEvent> list, bool slow)
    {
        var src = Attacker();
        var dst = $"10.0.1.{_rnd.Next(2, 60)}";
        var t = RandomTime();
        var ports = Enumerable.Range(1, 1024).OrderBy(_ => _rnd.Next()).Take(_rnd.Next(60, 300)).ToList();
        foreach (var p in ports)
        {
            t = t.AddMilliseconds(slow ? _rnd.Next(8000, 15000) : _rnd.Next(20, 200));
            list.Add(new FwEvent(t, "portscan", FwKind.Traffic, src, Ephemeral(), dst, p, "tcp", p is 443, true, "tcp/" + p, "incomplete", 0));
        }
    }

    private void Sweep(List<FwEvent> list)
    {
        var src = Attacker();
        var port = _rnd.Next(2) == 0 ? 445 : 3389;
        var t = RandomTime();
        for (var h = 2; h < _rnd.Next(40, 120); h++)
        {
            t = t.AddMilliseconds(_rnd.Next(100, 1500));
            list.Add(new FwEvent(t, "sweep", FwKind.Traffic, src, Ephemeral(), $"10.0.3.{h}", port, "tcp", false, true, "tcp/" + port, "incomplete", 0));
        }
    }

    private void BruteForce(List<FwEvent> list, bool slow)
    {
        var src = Attacker();
        var (port, svc) = _rnd.Next(2) == 0 ? (22, "SSH") : (3389, "RDP");
        var t = RandomTime();
        for (var i = 0; i < _rnd.Next(40, 160); i++)
        {
            t = t.AddMilliseconds(slow ? _rnd.Next(40_000, 90_000) : _rnd.Next(800, 4000));
            list.Add(new FwEvent(t, "bruteforce", FwKind.Traffic, src, Ephemeral(), "10.0.1.20", port, "tcp", true, true, svc,
                svc.ToLowerInvariant(), _rnd.Next(2000, 6000)));
        }
    }

    private void Flood(List<FwEvent> list)
    {
        var src = Attacker();
        var t = RandomTime();
        for (var i = 0; i < _rnd.Next(150, 400); i++)
        {
            t = t.AddMilliseconds(_rnd.Next(10, 150));
            list.Add(new FwEvent(t, "flood", FwKind.Traffic, src, Ephemeral(), $"10.0.1.{_rnd.Next(2, 6)}", 53, "udp", false, true, "DNS", "dns", 0));
        }
    }

    private void Beacon(List<FwEvent> list)
    {
        var src = Inside();
        var c2 = Attacker();
        var port = new[] { 4444, 1337, 6667, 31337 }[_rnd.Next(4)];
        var t = RandomTime();
        for (var i = 0; i < _rnd.Next(10, 40); i++)
        {
            t = t.AddSeconds(60 + _rnd.Next(-5, 6));
            list.Add(new FwEvent(t, "c2", FwKind.Traffic, src, Ephemeral(), c2, port, "tcp", true, false, "tcp/" + port, "unknown-tcp", _rnd.Next(200, 900)));
        }
    }

    private void Intrusion(List<FwEvent> list)
    {
        var src = Attacker();
        var t = RandomTime();
        for (var i = 0; i < _rnd.Next(2, 8); i++)
        {
            t = t.AddSeconds(_rnd.Next(1, 20));
            list.Add(new FwEvent(t, "intrusion", FwKind.Threat, src, Ephemeral(), WebServer, 443, "tcp", false, true,
                Threat: ThreatNames[_rnd.Next(ThreatNames.Length)]));
        }
    }

    private void AuthFailures(List<FwEvent> list)
    {
        var src = Attacker();
        var t = RandomTime();
        var users = new[] { "admin", "root", "vpnuser", "test", "fortinet" };
        for (var i = 0; i < _rnd.Next(6, 25); i++)
        {
            t = t.AddSeconds(_rnd.Next(3, 25));
            list.Add(new FwEvent(t, "authfail", FwKind.Auth, src, Ephemeral(), VpnGateway, 443, "tcp", false, true, User: users[_rnd.Next(users.Length)]));
        }
    }
}
