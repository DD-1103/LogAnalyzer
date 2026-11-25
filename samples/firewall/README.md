# Firewall log samples

**All data in these files is synthetic.** The lines were written by hand / generated after the vendors' *public*
documentation of their log formats (see "How far the formats are verified" below). They contain no real logs, nothing
from any employer, no real company or host names and no real public IP addresses: outside addresses are from the
documentation ranges (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24, 2001:db8::/32), inside addresses are RFC 1918,
domain names end in `example.com`, the AWS account id is the documentation id 123456789012, MAC addresses are from the
documentation block 00:00:5E:00:53:xx. `0.0.0.0` / `::` appear where a format writes "no address".

`tests/LogAnalyzer.Tests/FirewallSampleEndToEndTests.cs` checks every file in this folder: detected format, no unreadable
line, **exactly** the rules of the table below, no copied lines, time order, at least six different failed logins per
alert, and that every address is in the ranges above. A new sample must be added to the expected table of that test.

## What each file triggers (default firewall rules)

| File | Format id | Port scan | Network sweep | Brute force | C2 port | IPS / threat | Failed logins |
|------|-----------|:---------:|:-------------:|:-----------:|:-------:|:------------:|:-------------:|
| `aws-vpc-flow.log` | aws-vpc-flow | yes | yes | yes | yes | - (1) | - (1) |
| `cef.log` | cef | yes | | yes | yes | yes | yes |
| `checkpoint.log` | checkpoint | yes | | yes | yes | yes | yes |
| `cisco-asa.log` | cisco-asa | yes | | yes | yes | yes | yes |
| `fortigate.log` | fortigate | yes | | yes | yes | yes | yes |
| `generic-kv.log` | keyvalue | yes | | yes | yes | yes | yes |
| `huawei.log` | huawei | yes | | yes | yes | yes | yes |
| `iptables-ufw.log` | netfilter | yes | yes | yes | yes | - (2) | yes |
| `json.log` | json | yes | | yes | yes | yes | yes |
| `juniper-srx.log` | juniper-srx | yes | | yes | yes | yes | yes |
| `leef.log` | leef | yes | | yes | yes | yes | yes |
| `meraki.log` | meraki | yes | | yes | yes | yes | yes (6) |
| `mikrotik.log` | mikrotik | yes | | yes | yes | - (3) | yes |
| `paloalto.log` | paloalto | yes | | yes | yes | yes | yes |
| `pfsense.log` | pfsense | yes | yes | yes | yes | - (4) | - (4) |
| `sonicwall.log` | sonicwall | yes | | yes | yes | yes | yes |
| `sophos.log` | sophos | yes | | yes | yes | yes | yes |
| `stormshield.log` | stormshield | yes | | yes | yes | yes | yes |
| `watchguard.log` | watchguard | yes | | yes | yes | yes | yes |
| `windows-firewall.log` | windows-firewall | yes | | yes | yes | - (5) | - (5) |
| `zyxel.log` | zyxel | yes | | yes | yes | yes | yes |

"Flood of blocked connections" (100 in a minute) fires in none of them: the samples are small on purpose.

Why a rule is missing:

1. A VPC flow record is addresses, ports, counters and ACCEPT / REJECT. AWS writes no threat or login events into it.
2. The netfilter LOG target has no signatures. The failed logins are `sshd` lines of the same gateway syslog.
3. RouterOS has no signature-based IPS; its log has firewall rules with `action=log` and login messages.
4. `filterlog` only has packet-filter decisions. Snort / Suricata, GUI and sshd write other syslog programs.
5. `pfirewall.log` only has ALLOW / DROP lines. Windows logons are in the Security event log (4625).
6. **Not the documented line.** The Meraki documentation shows `type=anyconnect_vpn_auth_failure msg= 'Peer IP=192.168.0.1Peer
   port[8748] AAA[8]: AAA authenticate failed retval=7 - Authentication failure'` (as rendered there, maybe without a space), the
   address inside the text. The sample has an extra `remote_ip=` field, because the parser currently skips the documented
   line (2026-11-25). So this sample does **not** show that failed AnyConnect logins of a real MX are detected.

## The stories

Every file is one small incident on 21 November 2026. All attacks come from the outside; normal allowed traffic, some
single blocked packets and one or two device messages without traffic (skipped) are in every file that has such lines.

**Story A** (positional / text formats: aws-vpc-flow, cisco-asa, iptables-ufw, juniper-srx, mikrotik, paloalto, pfsense,
watchguard, windows-firewall), 10:00-10:16:

| Time | What happens |
|------|--------------|
| 10:00 | normal allowed traffic |
| 10:02 | **port scan** from 203.0.113.5: 21 destination ports in 40 s |
| 10:05-10:08 | **SSH or RDP brute force** from 203.0.113.9: 21 connections in 200 s |
| 10:05-10:06 | *iptables-ufw, mikrotik*: **failed SSH logins** (6 / 7), three seconds after the first connections |
| 10:10-10:11 | *aws-vpc-flow, iptables-ufw, pfsense*: **network sweep** from 198.51.100.23 over 21 hosts on port 445 in 80 s (it also triggers the brute-force rule: 21 connections to port 445) |
| 10:11-10:12 | *cisco-asa, juniper-srx, paloalto, watchguard*: **IPS / threat events** from 192.0.2.44 |
| 10:13 | *cisco-asa, juniper-srx, paloalto, watchguard*: 6-7 **failed logins** on the firewall from 203.0.113.9 in 26-45 s |
| 10:13-10:14 | *cisco-asa, paloalto, iptables-ufw*: a user mistypes the password once, then signs in (**no alert**) |
| 10:15 | an inside host connects out to **port 4444** |

**Story B** (key=value / structured formats: cef, checkpoint, fortigate, generic-kv, huawei, json, leef, meraki, sonicwall,
sophos, stormshield, zyxel), 10:00-10:55 UTC (`fortigate.log` writes local time with `tz="+0100"`):

| Time | What happens |
|------|--------------|
| 10:00-10:05 | normal allowed traffic (HTTPS, DNS, HTTP) from 10.0.0.21/22 and 192.168.1.15/16 |
| 10:10 | **port scan** from 203.0.113.50: 24 destination ports (20-43) in 47 s, all denied |
| 10:20-10:23 | **SSH brute force** from 203.0.113.77: 22 connections to port 22 in 3.5 min |
| 10:30 | 3 **IPS / threat events** from 192.0.2.66 (SQL injection, directory traversal, remote code execution) |
| 10:40-10:41 | 6 **failed admin / VPN logins** from 192.0.2.99 in 63 s, each with its own time and, where the format has one, source port / sequence |
| 10:50 | 10.0.0.23 connects out to 198.51.100.200 **port 4444** (Check Point: prevented by Anti-Bot, so it is also a threat event) |

## Files

| File | Vendor / product | Content |
|------|------------------|---------|
| `aws-vpc-flow.log` | AWS VPC Flow Logs, default version 2 with header line | ACCEPT / REJECT records, one NODATA record (skipped) |
| `cef.log` | any device exporting CEF (made-up "ExampleSec EdgeFW") | `rt` as text and as epoch ms, `cs1Label=Rule`, `cs2Label=Threat Name` |
| `checkpoint.log` | Check Point Log Exporter | RFC 5424 structured data `[k:"v"; ...]` plus one plain key=value line |
| `cisco-asa.log` | Cisco ASA / FTD syslog | 106023, 302013/302014, 400010, 733101, 106017, 419002, 605004, 113015, 716039, 113039, 710003, 313001, 106100, skipped 111008 / 305011 |
| `fortigate.log` | Fortinet FortiGate (FortiOS) | traffic, utm ips, event system (32002) and vpn (39426) |
| `generic-kv.log` | an unknown vendor (`gw-branch fwd`) | plain key=value with common key names |
| `huawei.log` | Huawei USG / HiSecEngine | POLICYDENY / POLICYPERMIT, SECLOG SESSION_TEARDOWN, IPS DETECT, SSH login failure |
| `iptables-ufw.log` | Linux netfilter: UFW, firewalld, nftables, Ubiquiti UniFi prefixes, sshd of the gateway | UFW BLOCK / ALLOW / LIMIT BLOCK, FINAL_REJECT, nft drop, WAN_IN-default-D, "Failed password" |
| `json.log` | JSON lines of several products | scan = ECS + Azure, brute force = GCP + AWS Network Firewall netflow, threats = AWS alerts, logins = ECS, 4444 = OPNsense |
| `juniper-srx.log` | Juniper SRX | RT_FLOW text + structured data, RT_IDP, RT_SCREEN, SSHD_LOGIN_FAILED, skipped UI_ / SNMP_ |
| `leef.log` | any device exporting LEEF (made-up "ExampleSec EdgeFW") | LEEF 1.0 (tab) and 2.0 (`^`) with devTime + devTimeFormat |
| `meraki.log` | Cisco Meraki MX | flows / firewall / ids-alerts / security_event / events |
| `mikrotik.log` | MikroTik RouterOS | firewall log with prefixes (TCP, ICMP, IPv6), login failures |
| `paloalto.log` | Palo Alto Networks PAN-OS syslog CSV | TRAFFIC, THREAT, SYSTEM auth-fail, GLOBALPROTECT, CONFIG |
| `pfsense.log` | pfSense / OPNsense filterlog | BSD and RFC 5424 headers, IPv4 + IPv6, ICMP |
| `sonicwall.log` | SonicWall (SonicOS) | `src=ip:port:interface`, message ids m=36/98/537/82/83/30/1080 |
| `sophos.log` | Sophos Firewall (SFOS / XG) | old `date= time= timezone=` lines and the newer `timestamp=` variant |
| `stormshield.log` | Stormshield SNS | logtype filter / alarm / auth / system |
| `watchguard.log` | WatchGuard Fireware | traffic 3000-0148 / 0151, IPS (signature_name), authentication |
| `windows-firewall.log` | Windows Defender Firewall | pfirewall.log, W3C header with pid, INFO-EVENTS-LOST (skipped) |
| `zyxel.log` | Zyxel USG / ATP (ZLD) | no own date: the syslog time is used |

## How far the formats are verified

Nothing was compared with a real device. The documentation pages were opened on 2026-11-25:

* **checked** - the page was opened and shows the layout named in the last column;
* **opened** - the page exists but does not show the line format (index, overview or how-to page);
* **not verified** - the page could not be opened (or the link only leads to a start page).

| File | Documentation | Status | Remark |
|------|---------------|--------|--------|
| `aws-vpc-flow.log` | https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html | checked | field order, ACCEPT / REJECT, NODATA; no login or threat field exists |
| `pfsense.log` | https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html | checked | field order including ICMP echo |
| `fortigate.log` | https://docs.fortinet.com/document/fortigate/7.4.0/fortios-log-message-reference (32002: `.../32002/32002-log-id-admin-login-fail`) | checked (32002 only) | traffic, ips and 39426 lines not checked |
| `paloalto.log` | https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions | checked (System log only) | index page; the `system-log-fields` page has the field order of the auth-fail lines; the other log types not checked |
| `meraki.log` | https://documentation.meraki.com/General_Administration/Monitoring_and_Reporting/Syslog_Event_Types_and_Log_Samples | checked | flows and ids_alerted fields as documented; the AnyConnect failure line is **different** (note 6 above) |
| `leef.log` | https://www.ibm.com/docs/en/dsm?topic=leef-overview, https://www.ibm.com/docs/en/dsm?topic=overview-leef-event-components | checked (header) | header order and 2.0 delimiter on the second page |
| `json.log` (AWS Network Firewall) | https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-logging-contents.html | checked (alert) | netflow events are only named there, no example |
| `cisco-asa.log` | https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog.html | checked (302013 / 302015) | the guide covers the id ranges; it does not say that "for" is the outside end also for outbound connections; login messages not checked |
| `sophos.log` | https://docs.sophos.com/nsg/sophos-firewall/21.0/syslog/ | checked in part | "SSL VPN Authentication" + `status="Failed"` documented; a failed *admin* login line was not found (`log_component="Admin"` not verified). The earlier link https://docs.sophos.com/nsg/sophos-firewall/ is 404 |
| `mikrotik.log` | https://help.mikrotik.com/docs/spaces/ROS/pages/328094/Log, https://help.mikrotik.com/docs/spaces/ROS/pages/48660574/Filter | opened | firewall log example and log prefixes shown, the login-failure message is not |
| `checkpoint.log` | https://support.checkpoint.com/results/sk/sk122323 | opened | names the export formats, no example line |
| `windows-firewall.log` | https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-logging | opened | how to switch logging on; no field list, so the `#Fields` order is not verified there |
| `iptables-ufw.log` | https://www.netfilter.org/documentation/, https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html, https://firewalld.org/documentation/ | opened | index / manual pages without example log lines; sshd messages are OpenSSH's |
| `json.log` (ECS) | https://www.elastic.co/guide/en/ecs/current/index.html | opened | field reference index |
| `json.log` (Azure) | https://learn.microsoft.com/azure/firewall/firewall-structured-logs | opened | redirects to "Monitor Azure Firewall", lists the tables, not the columns |
| `json.log` (Google Cloud) | https://cloud.google.com/firewall/docs/firewall-rules-logging | opened | moved to docs.cloud.google.com; the JSON field names are not on the page |
| `json.log` (OPNsense) | https://docs.opnsense.org/manual/logging_firewall.html | opened | names label and rid only. The earlier link https://docs.opnsense.org/manual/logging.html is 404 |
| `sonicwall.log` | https://www.sonicwall.com/support/technical-documentation/ (SonicOS Log Events Reference Guide) | not verified | only a start page |
| `zyxel.log` | https://www.zyxel.com/ (ZLD Log Reference Guide) | not verified | only a start page |
| `huawei.log` | https://support.huawei.com/enterprise/en/doc/ (USG6000 / HiSecEngine Log Reference) | not verified | empty page; `SSH_USER_LOGIN_FAIL` not verified |
| `stormshield.log` | https://documentation.stormshield.eu/SNS/v4/en/Content/Description_of_Audit_logs/ | not verified | HTTP 403; the `logtype="auth"` line not verified |
| `cef.log` | https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdoc/common-event-format-v25/common-event-format-v25.pdf | not verified | HTTP 403 |
| `juniper-srx.log` | https://www.juniper.net/documentation/us/en/software/junos/syslog-monitoring/topics/topic-map/security-log-messages.html | not verified | redirects to another host, 404 there |
| `watchguard.log` | https://www.watchguard.com/help/docs/fireware/12/en-US/log_catalog/Log-Catalog_v12_10.pdf | not verified | HTTP 404; the authentication message ids not verified |
| `generic-kv.log` | none | - | an invented key=value log |
