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

# Firewall log samples

All files in this folder are **synthetic**. They were written by hand / generated from the vendors' public
documentation, use only documentation address ranges for the outside (203.0.113.0/24, 198.51.100.0/24,
192.0.2.0/24, 2001:db8::/32) and RFC 1918 addresses inside, generic host names and the AWS documentation account id
123456789012. They contain no real logs, no real company data and nothing from any employer.

## Positional / text formats

Every file tells the same small story on 21 Nov 2026 around 10:00 so the firewall rules have something to find:
normal allowed traffic (10:00), a **port scan** from 203.0.113.5 (21 destination ports in 40 s, 10:02),
an **SSH / RDP brute force** from 203.0.113.9 (21 connections to 22 or 3389 in 200 s, 10:05), IPS / threat events from
192.0.2.44 (10:11-10:12, where the vendor logs them), **failed logins** (10:13, where the vendor logs them),
an inside host connecting out to **port 4444** (10:15) and a few lines the parser skips. Files marked *sweep* also
contain a **network sweep** from 198.51.100.23 to 21 inside hosts on port 445 within 80 s (10:10).

| File | Vendor / format | Documentation followed | Story |
|------|-----------------|------------------------|-------|
| `paloalto.log` | Palo Alto Networks PAN-OS syslog CSV (TRAFFIC, THREAT, SYSTEM auth-fail, GLOBALPROTECT, CONFIG) | https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions | scan (deny-all), SSH brute force + IPS "SSH User Authentication Brute Force Attempt", SQL injection / traversal threats, admin and GlobalProtect login failures, 4444 outbound |
| `cisco-asa.log` | Cisco ASA / FTD syslog (106023, 302013/302014, 400010, 733101, 106017, 419002, 605004, 113015, 716039, 113039, 710003, 313001, 106100, skipped 111008 / 305011) | https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog.html | scan (106023 denies), SSH brute force (302013), IPS / threat detection, login failures, 4444 outbound (302013 outbound) |
| `pfsense.log` | pfSense / OPNsense filterlog, BSD and RFC 5424 headers, IPv4 + IPv6 | https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html | scan, SSH brute force (pass), *sweep* on 445, 4444 outbound, ICMP, IPv6 |
| `iptables-ufw.log` | Linux netfilter: UFW, firewalld, nftables, Ubiquiti UniFi prefixes | https://www.netfilter.org/documentation/ (LOG target), https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html, https://firewalld.org/documentation/ | scan (UFW BLOCK / FINAL_REJECT / nft drop), SSH brute force (UFW ALLOW then UFW LIMIT BLOCK), *sweep* on 445 (UniFi WAN_IN-default-D), 4444 outbound |
| `windows-firewall.log` | Windows Defender Firewall pfirewall.log (W3C header with pid) | https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-logging | scan (DROP), RDP brute force on 3389, 4444 SEND, INFO-EVENTS-LOST |
| `juniper-srx.log` | Juniper SRX: RT_FLOW text + structured-data, RT_IDP, RT_SCREEN, SSHD_LOGIN_FAILED, skipped UI_ / SNMP_ | https://www.juniper.net/documentation/us/en/software/junos/syslog-monitoring/topics/topic-map/security-log-messages.html | scan (RT_FLOW_SESSION_DENY + screen "TCP port scan"), SSH brute force (structured RT_FLOW_SESSION_CREATE), IDP SQL injection / traversal, ICMP flood, SSH login failures, 4444 outbound |
| `watchguard.log` | WatchGuard Fireware traffic (3000-0148 / 3000-0151), IPS (signature_name), authentication | https://www.watchguard.com/help/docs/fireware/12/en-US/log_catalog/Log-Catalog_v12_10.pdf | scan (Unhandled External Packet), RDP brute force, IPS SQL injection / traversal, Firebox login failures, 4444 outbound |
| `mikrotik.log` | MikroTik RouterOS firewall log with prefixes (TCP, ICMP, IPv6) and system login messages | https://help.mikrotik.com/docs/spaces/ROS/pages/328094/Log, https://help.mikrotik.com/docs/spaces/ROS/pages/48660574/Filter | scan (DROP-WAN), SSH brute force (ACCEPT-SSH) + login failures, ICMP, IPv6, 4444 forward |
| `aws-vpc-flow.log` | AWS VPC Flow Logs, default version 2 with header line, NODATA record | https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html | scan (REJECT), SSH brute force (ACCEPT), *sweep* on 445, 4444 outbound |
