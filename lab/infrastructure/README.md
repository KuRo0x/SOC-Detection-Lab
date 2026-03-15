# Lab Host Inventory

All virtual machines running in VMware Workstation on the same host. Internal lab network is **VMnet3 — 172.16.0.0/24**.

---

## VM Overview

| Hostname | OS | IP Address | RAM | CPU | Disk | Role |
|---|---|---|---|---|---|---|
| pfsense | FreeBSD (pfSense 2.x) | 172.16.0.1 (LAN) | 480 MB | 1 vCPU | 15 GB | Firewall / Gateway |
| soc-brn-ubn | Ubuntu 24.04.3 LTS | 172.16.0.4 | 3.8 GB | 2 vCPU | 28.37 GB | SIEM / IDS |
| DESKTOP-DPU3CDQ | Windows 10 x64 | 172.16.0.10 | 2 GB | 2 vCPU | — | Victim Endpoint |
| kali | Kali Linux (rolling) | 172.16.0.11 | 3.8 GB | 2 vCPU | — | Attacker |

---

## Network Layout

```
[ Internet ]
      |
   [ NAT ]
      |
  [ pfSense ]  172.16.0.1
      |
  [ VMnet3 — 172.16.0.0/24 ]
      |           |             |
  soc-brn-ubn  DESKTOP-DPU3CDQ  kali
  172.16.0.4   172.16.0.10     172.16.0.11
  (SIEM/IDS)   (Victim)        (Attacker)
```

---

## Per-Host Details

### pfSense — Firewall / Gateway
| Field | Value |
|---|---|
| OS | FreeBSD (pfSense) |
| WAN | NAT (VMware NAT) |
| LAN | 172.16.0.1 — VMnet3 |
| RAM | 480 MB |
| CPU | 1 vCPU |
| Disk | 15 GB |
| Role | Network perimeter, traffic control, Suricata IDS inline |

### soc-brn-ubn — SIEM / IDS
| Field | Value |
|---|---|
| OS | Ubuntu 24.04.3 LTS (kernel 6.8.0-88-generic) |
| IP | 172.16.0.4/24 (ens33) |
| MAC | 00:0c:29:82:62:3a |
| RAM | 3.8 GB |
| CPU | 2 vCPU |
| Disk | 28.37 GB |
| Services | Elasticsearch, Logstash, Kibana, Suricata |
| Role | Central SIEM, network IDS, log aggregation |

### DESKTOP-DPU3CDQ — Victim Endpoint
| Field | Value |
|---|---|
| OS | Windows 10 x64 |
| IP | 172.16.0.10/24 |
| RAM | 2 GB |
| CPU | 2 vCPU |
| User | END-Alex |
| Services | Sysmon, Winlogbeat |
| Role | Target machine for adversary emulation scenarios |

### kali — Attacker
| Field | Value |
|---|---|
| OS | Kali Linux (rolling) |
| IP | 172.16.0.11/24 (eth0) |
| RAM | 3.8 GB |
| CPU | 2 vCPU |
| Role | Adversary simulation, red team tooling |
