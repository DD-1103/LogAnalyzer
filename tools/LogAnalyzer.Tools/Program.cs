using LogAnalyzer.Tools;

// Command-line helpers for the evaluation chapter (RQ1-RQ3).
//   generate     synthetic labelled access log of any size (performance test, RQ3)
//   generate-firewall  synthetic labelled firewall log (FortiGate, Palo Alto, Cisco ASA, iptables or CEF)
//   csic         convert the CSIC 2010 HTTP dataset to Combined Log Format + labels (RQ1)
//   label-by-ip  label a lab log (DVWA + Kali) by attacker IP and tool user agent (RQ1/RQ2)
//   bench        parse + detect a file in memory, without the database (RQ3)

var parsed = Args.Parse(args);
try
{
    return parsed.Command switch
    {
        "generate" => Generator.Run(parsed),
        "generate-firewall" => FirewallGenerator.Run(parsed),
        "detect" => DetectFormat.Run(parsed),
        "csic" => CsicConverter.Run(parsed),
        "label-by-ip" => LabelByIp.Run(parsed),
        "bench" => await Bench.RunAsync(parsed),
        _ => Usage()
    };
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine("Error: " + ex.Message);
    Console.Error.WriteLine();
    return Usage();
}

static int Usage()
{
    Console.WriteLine("""
        LogAnalyzer tools

          generate     --lines 1000000 --out big.log [--labels big.labels.csv] [--attack-ratio 0.02] [--seed 42]
                       Synthetic Combined-format log with ground-truth labels: normal browsing, search-engine
                       crawlers, monitoring, and SQLi/XSS/traversal/brute-force/enumeration/scanner campaigns
                       (including evasive variants the default rules miss).

          generate-firewall --lines 100000 --out fw.log [--format fortigate|paloalto|cisco-asa|iptables|cef]
                       [--labels fw.labels.csv] [--attack-ratio 0.03] [--seed 42]
                       Synthetic labelled firewall log (documentation IP ranges only): normal traffic, internet
                       noise, a monitoring host, an authorised vulnerability scanner (a deliberate false positive),
                       and port scans, sweeps, brute force, floods, C2 beacons, IPS events (not for iptables) and
                       failed logins (slow, evasive variants included).

          detect       --log fw.log [--show-failed 5]
                       Shows which format the app detects for a file and how many lines it can read
                       (same detector as the upload), with the first lines it could not read.

          csic         --normal normalTrafficTest.txt --anomalous anomalousTrafficTest.txt --out csic.log
                       [--labels csic.labels.csv] [--body-as-query] [--seed 42]
                       Converts the CSIC 2010 HTTP dataset. Access logs never contain POST bodies; with
                       --body-as-query the body is appended to the URL (upper bound for signature rules).

          label-by-ip  --log access.log --attackers 192.168.56.101[,ip2] --out labels.csv
                       Labels a lab log: lines from attacker IPs = attack (type guessed from the tool's
                       user agent: sqlmap, hydra, nikto, gobuster/dirb/ffuf/wfuzz), all others = normal.

          bench        --log big.log [--repeat 1]
                       Parses the file and runs the default rules + Isolation Forest in memory and prints
                       throughput (lines/s). Isolates CPU cost from SQL Server import time.
        """);
    return 1;
}
