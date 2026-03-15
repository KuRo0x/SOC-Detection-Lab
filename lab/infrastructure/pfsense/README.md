# pfSense

> Network gateway and enforcement point for the lab. All traffic between VMs and the internet flows through pfSense. Containment, DNS enforcement, and traffic logging are handled here.

---

## Platform

| Field | Value |
|---|---|
| Version | 2.8.1-RELEASE (amd64) |
| OS | FreeBSD 15.0-CURRENT |
| Platform | VMware Virtual Machine |
| Hostname | pfSense.home.arpa |

---

## Network Interfaces

| Interface | Adapter | Network | IP | Subnet | Role |
|---|---|---|---|---|---|
| WAN | em0 | NAT (VMnet8) | 192.168.164.129 | /24 | Internet access via host |
| LAN | em1 | VMnet3 | 172.16.0.1 | /24 | Internal lab gateway |

---

## DNS

All DNS queries from lab VMs are forced through pfSense. Direct external DNS is blocked at the firewall level.

| Resolver | Role |
|---|---|
| 127.0.0.1 | pfSense local resolver |
| 8.8.8.8 | Upstream (Google) |
| 1.1.1.1 | Upstream (Cloudflare) |

---

## Firewall Rules — LAN

| # | State | Protocol | Source | Destination | Port | Purpose |
|---|---|---|---|---|---|---|
| 1 | ✅ | Any | Any | LAN Address | 80 | Anti-lockout (WebUI access) |
| 2 | ❌ | IPv4 TCP | Any | ATTACKER_KALI_INC001 | WEB_PORTS | Block attacker C2 infrastructure (INC-001) |
| 3 | ✅ | IPv4 TCP/UDP | LAN | This Firewall | 53 | Force DNS through pfSense |
| 4 | ❌ | IPv4 TCP/UDP | LAN | Any | 53 | Block direct DNS bypass |
| 5 | ✅ | IPv4 | LAN | Any | Any | Default outbound allow |
| 6 | ✅ | IPv6 | LAN | Any | Any | Default outbound allow (IPv6) |

### Aliases

| Alias | Type | Value | Created For |
|---|---|---|---|
| ATTACKER_KALI_INC001 | Host | Attacker Kali VM IP | INC-001 containment |
| WEB_PORTS | Port | TCP 80, 443 | Web traffic blocking |

---

## Lab Role

- **Single enforcement point** — every VM on VMnet3 routes through pfSense
- **DNS control** — no VM can bypass the resolver
- **Incident containment** — attacker infrastructure blocked at network level via aliases
- **Traffic visibility** — all blocked traffic logged for SIEM ingestion
