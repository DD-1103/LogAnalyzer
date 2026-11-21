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
