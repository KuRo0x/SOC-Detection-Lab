# Lab Host Inventory

All virtual machines running in VMware Workstation on the same host. Internal lab network is **VMnet3 — 172.16.0.0/24**.

---

## VM Overview

| Hostname | OS | IP Address | RAM | CPU | Disk | Role |
|---|---|---|---|---|---|---|
| pfsense | FreeBSD (pfSense 2.x) | 172.16.0.1 (LAN) | 480 MB | 1 vCPU | 15 GB | Firewall / Gateway |
| soc-brn-ubn | Ubuntu 24.04.3 LTS | 172.16.0.4 | 3.8 GB | 2 vCPU | 28.37 GB | SIEM / IDS |
| DESKTOP-DPU3CDQ | Windows 10 x64 | 172.16.0.10 | 2 GB | 2 vCPU | — | Windows Victim Endpoint |
| ubuntu-victim | Ubuntu Linux | 172.16.0.20 | — | — | — | Linux Victim Endpoint |
| kali | Kali Linux (rolling) | 172.16.0.11 | 3.8 GB | 2 vCPU | — | Attacker |

> `ubuntu-victim` was added during **INC-009 — SSH Brute Force** to serve as a dedicated Linux target host. It ships `/var/log/auth.log` to Elasticsearch via Filebeat 8.19.15.

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
      |              |                |               |
  soc-brn-ubn  DESKTOP-DPU3CDQ  ubuntu-victim       kali
  172.16.0.4   172.16.0.10      172.16.0.20         172.16.0.11
  (SIEM/IDS)   (Win Victim)     (Linux Victim)       (Attacker)
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

### DESKTOP-DPU3CDQ — Windows Victim Endpoint
| Field | Value |
|---|---|
| OS | Windows 10 x64 |
| IP | 172.16.0.10/24 |
| RAM | 2 GB |
| CPU | 2 vCPU |
| User | END-Alex |
| Services | Sysmon, Winlogbeat |
| Role | Target machine for adversary emulation scenarios |

### ubuntu-victim — Linux Victim Endpoint
| Field | Value |
|---|---|
| OS | Ubuntu Linux |
| IP | 172.16.0.20/24 |
| RAM | — |
| CPU | — |
| Services | SSH (TCP 22), Filebeat 8.19.15 |
| Log source | `/var/log/auth.log` |
| Elastic index | `filebeat-*` |
| ECS status | Raw messages only — no full SSH ECS field parsing yet |
| Role | Linux target host for SSH brute-force and auth log detection |
| Added in | [INC-009 — SSH Brute Force](../../incidents/INC-009-ssh-bruteforce/) |

> **Note:** `source.ip`, `user.name`, and `event.outcome` are not yet parsed into ECS fields from raw auth log messages. Detection relies on `message` string matching. An ingest pipeline or Logstash grok filter is the next engineering step.

### kali — Attacker
| Field | Value |
|---|---|
| OS | Kali Linux (rolling) |
| IP | 172.16.0.11/24 (eth0) |
| RAM | 3.8 GB |
| CPU | 2 vCPU |
| Role | Adversary simulation, red team tooling |
