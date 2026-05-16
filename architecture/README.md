# Lab Architecture

This folder contains the network topology diagram for the KuRo SOC Detection Lab.

---

## Network Topology

```
[ Internet ]
      |
   [ NAT ]
      |
  [ pfSense ]  172.16.0.1  — Firewall / Gateway / Suricata IDS
      |
  [ VMnet3 — 172.16.0.0/24 — Isolated Lab Network ]
      |              |                |               |
  soc-brn-ubn   DESKTOP-DPU3CDQ   ubuntu-victim    kali
  172.16.0.4    172.16.0.10       172.16.0.20      172.16.0.11
  (SIEM/IDS)    (Windows Victim)  (Linux Victim)   (Attacker)
```

---

## Diagram File

> `architecture-diagram.png` — place the exported network diagram image in this folder.

---

## What the Diagram Shows

| Element | Detail |
|---|---|
| Network | Isolated VMnet3 — `172.16.0.0/24` |
| Perimeter | pfSense firewall as the single enforced gateway |
| SIEM | Ubuntu server running ELK Stack + Suricata IDS |
| Windows Endpoint | Windows 10 victim with Sysmon + Winlogbeat |
| Linux Endpoint | Ubuntu victim with Filebeat + SSH (added INC-009) |
| Attacker | Kali Linux with Hydra, Nmap, Metasploit, Impacket |

---

## Data Flows

| Source | Destination | Protocol | Data |
|---|---|---|---|
| DESKTOP-DPU3CDQ | soc-brn-ubn | Winlogbeat TCP 5044 | Windows Event Logs + Sysmon |
| ubuntu-victim | soc-brn-ubn | Filebeat TCP 5044 | `/var/log/auth.log` |
| pfSense | soc-brn-ubn | Suricata EVE JSON / Syslog UDP 5140 | IDS alerts + firewall logs |
| kali | ubuntu-victim | SSH TCP 22 | Attack traffic (INC-009) |
| kali | DESKTOP-DPU3CDQ | SMB / WinRM | Attack traffic (INC-004, 008) |
| kali | pfSense | Blocked TCP 22 | Post-INC-009 firewall block |

---

## VM Inventory Quick Reference

| Hostname | OS | IP | Role |
|---|---|---|---|
| `pfsense` | FreeBSD (pfSense 2.x) | `172.16.0.1` | Firewall · Gateway · Suricata IDS |
| `soc-brn-ubn` | Ubuntu 24.04.3 LTS | `172.16.0.4` | SIEM · ELK Stack · Kibana |
| `DESKTOP-DPU3CDQ` | Windows 10 x64 | `172.16.0.10` | Windows Victim · Sysmon · Winlogbeat |
| `ubuntu-victim` | Ubuntu Linux | `172.16.0.20` | Linux Victim · Filebeat · SSH target |
| `kali` | Kali Linux (rolling) | `172.16.0.11` | Attacker · Adversary Emulation |

> Full per-host details: [`lab/infrastructure/README.md`](../lab/infrastructure/README.md)
