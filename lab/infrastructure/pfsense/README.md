# pfSense — Lab Firewall & Gateway

## System Information

| Field | Value |
|---|---|
| Hostname | pfSense.home.arpa |
| Version | 2.8.1-RELEASE (amd64) |
| Built | Wed Nov 26 22:12:00 +01 2025 |
| OS | FreeBSD 15.0-CURRENT |
| Platform | VMware Virtual Machine |
| CPU | 12th Gen Intel Core i5-12450H |
| AES-NI | Yes (inactive) |
| Kernel PTI | Enabled |

---

## Network Interfaces

| Interface | VMware Adapter | Network | IP Address | Subnet | Gateway | MAC |
|---|---|---|---|---|---|---|
| WAN | Network Adapter 1 | NAT (VMnet8) | 192.168.164.129 | /24 | 192.168.164.2 | 00:0c:29:95:38:a5 |
| LAN | Network Adapter 2 | Custom (VMnet3) | 172.16.0.1 | /24 | — | 00:0c:29:95:38:af |

> **WAN** uses NAT to share the host machine's internet connection.
> **LAN** is on VMnet3 — the isolated internal lab network where all VMs communicate.

---

## DNS Configuration

| DNS Server | Purpose |
|---|---|
| 127.0.0.1 | Local resolver |
| ::1 | Local resolver (IPv6) |
| 8.8.8.8 | Google DNS (upstream) |
| 1.1.1.1 | Cloudflare DNS (upstream) |

---

## Firewall Rules — LAN

| State | Protocol | Source | Destination | Port | Description |
|---|---|---|---|---|---|
| ✅ Active | * | * | LAN Address | 80 | Anti-Lockout Rule |
| ❌ Disabled | IPv4 TCP | * | ATTACKER_KALI_INC001 | WEB_PORTS | BLOCK outbound HTTPS/HTTP to known phishing host |
| ✅ Active | IPv4 TCP/UDP | LAN subnets | This Firewall (self) | 53 (DNS) | ALLOW DNS to pfSense |
| ❌ Disabled | IPv4 TCP/UDP | LAN subnets | * | 53 (DNS) | BLOCK direct DNS (no bypass) |
| ✅ Active | IPv4 * | LAN subnets | * | * | Default allow LAN to any rule |
| ✅ Active | IPv6 * | LAN subnets | * | * | Default allow LAN IPv6 to any rule |

### Rule Notes
- **ATTACKER_KALI_INC001** — firewall alias created during INC-001 containment to block attacker Kali infrastructure
- **WEB_PORTS** — alias covering TCP 80 and 443
- DNS enforcement rules prevent clients from bypassing pfSense resolver and querying external DNS directly
- Block rules are currently disabled (lab not under active attack)

---

## Role in Lab

- Acts as the **sole gateway** for the internal LAN (172.16.0.1/24)
- **WAN** connects to the internet via NAT through the host
- **LAN (VMnet3)** is the isolated segment connecting all lab VMs
- Enforces **DNS policy** — all DNS goes through pfSense resolver
- Provides **network-level containment** during incident response
- Logs all blocked traffic for SIEM correlation
