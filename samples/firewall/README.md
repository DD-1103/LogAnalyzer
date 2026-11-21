# Firewall sample logs (key=value and structured formats)

**All data in these files is synthetic.** The lines were written by hand / generated from the vendors' *public*
documentation of their log formats. They contain no real logs, no data from any employer, no real company or
host names and no real public IP addresses: outside addresses are from the documentation ranges
(203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24, 2001:db8::/32), inside addresses are RFC 1918
(10.0.0.0/8, 192.168.0.0/16), devices are called `fw01`, `gw01`, `usg-lab`, `mx-lab`, ... and the CEF / LEEF vendor is
the made-up "ExampleSec EdgeFW".

## The story (same in every file, 2026-11-21, 10:00-10:55 UTC)

| Time | What happens | Source -> destination | Rule it should trigger |
|------|--------------|-----------------------|------------------------|
| 10:00-10:05 | normal allowed traffic (HTTPS, DNS, HTTP) | 10.0.0.21/22, 192.168.1.15/16 -> 198.51.100.20-24 | none |
| 10:05 | device message without addresses (skipped) | - | none |
| 10:10:00-10:10:46 | **port scan**: 24 destination ports (20-43) in 47 s, all denied | 203.0.113.50 -> 10.0.0.5 | port scan |
| 10:20:00-10:23:30 | **SSH brute force**: 22 connections to port 22 in 3.5 min | 203.0.113.77 -> 10.0.0.10:22 | brute force |
| 10:30 | **3 IPS / threat events** (SQL injection, directory traversal, RCE) | 192.0.2.66 -> 10.0.0.5:80 | intrusion |
| 10:40 | **3 failed admin / VPN logins** | 192.0.2.99 -> 198.51.100.1 | authentication failure |
| 10:50 | **outbound to port 4444** (typical backdoor / C2 port) | 10.0.0.23 -> 198.51.100.200:4444 | suspicious outbound |
| 10:55 | device message without addresses (skipped) | - | none |

## Files

| File | Vendor / product | Format reference (public documentation) | Notes |
|------|------------------|------------------------------------------|-------|
| `fortigate.log` | Fortinet FortiGate (FortiOS) | FortiOS Log Message Reference, https://docs.fortinet.com/document/fortigate/7.4.0/fortios-log-message-reference | local time with `tz="+0100"`, traffic / utm ips / event system + vpn |
| `sophos.log` | Sophos Firewall (SFOS / XG) | Sophos Firewall help, log file details, https://docs.sophos.com/nsg/sophos-firewall/ | old `date= time= timezone=` lines and the SFOS v19+ `timestamp=` variant |
| `sonicwall.log` | SonicWall (SonicOS) | SonicOS Log Events Reference Guide, https://www.sonicwall.com/support/technical-documentation/ | `src=ip:port:interface`, message ids m=36/98/537/82/83/30/1080 |
| `checkpoint.log` | Check Point (Log Exporter) | sk122323 "Log Exporter - Check Point log export", https://support.checkpoint.com/results/sk/sk122323 | RFC 5424 structured data `[k:"v"; ...]` plus one plain key=value line |
| `huawei.log` | Huawei USG / HiSecEngine | HUAWEI USG6000 / HiSecEngine Log Reference, https://support.huawei.com/enterprise/en/doc/ | POLICYDENY / POLICYPERMIT, SECLOG SESSION_TEARDOWN, IPS DETECT, SSH login failure |
| `meraki.log` | Cisco Meraki MX | Syslog Event Types and Log Samples, https://documentation.meraki.com/General_Administration/Monitoring_and_Reporting/Syslog_Event_Types_and_Log_Samples | flows / firewall / ids-alerts / security_event / events |
| `stormshield.log` | Stormshield SNS | Description of audit logs, https://documentation.stormshield.eu/SNS/v4/en/Content/Description_of_Audit_logs/ | logtype filter / alarm / auth / system, `tz=+0000` |
| `zyxel.log` | Zyxel USG / ATP (ZLD) | ZLD Log Reference Guide (USG / ATP / USG FLEX download library), https://www.zyxel.com/ | no own date: the syslog time is used |
| `cef.log` | any device exporting CEF | ArcSight Common Event Format (CEF) Implementation Standard v25, https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdoc/common-event-format-v25/common-event-format-v25.pdf | `rt` as text and as epoch ms, `cs1Label=Rule`, `cs2Label=Threat Name` |
| `leef.log` | any device exporting LEEF | IBM QRadar LEEF overview, https://www.ibm.com/docs/en/dsm?topic=leef-overview | LEEF 1.0 (tab) and 2.0 (`^` delimiter) with devTime + devTimeFormat |
| `json.log` | JSON lines: Elastic Common Schema, AWS Network Firewall, Azure Firewall, Google Cloud firewall rules logging, OPNsense | https://www.elastic.co/guide/en/ecs/current/index.html, https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-logging.html, https://learn.microsoft.com/azure/firewall/firewall-structured-logs, https://cloud.google.com/firewall/docs/firewall-rules-logging, https://docs.opnsense.org/manual/logging.html | scan = ECS + Azure, brute force = GCP + AWS netflow, threats = AWS alerts, logins = ECS, 4444 = OPNsense |
| `generic-kv.log` | an unknown vendor (`gw-branch fwd`) | none: plain `key=value` with common key names | read by the generic key=value reader |

Format details that could not be checked against a real device (documentation only): the Meraki AnyConnect
authentication-failure event, the Stormshield `logtype="auth"` line and the Huawei `SSH_USER_LOGIN_FAIL` message.
