# Lab Inventory

This document lists the confirmed components, services, and roles present in the SOC Detection Lab environment.

---

## 1. Environment Overview

- **Lab Type:** Virtual Security Operations Center (SOC)
- **Network Mode:** Isolated virtual network (VMnet3)
- **Purpose:** Detection engineering, log ingestion, and SOC-style analysis
- **Scope:** Defensive monitoring only

---

## 2. Virtual Machines

### 2.1 Ubuntu Server — SIEM Node

**Role:** Central SIEM, log processing, detection engine  
**Installed Services:**
- Elasticsearch (search + storage)
- Logstash (log ingestion and processing)
- Kibana (visualization and analysis)
- Suricata (network intrusion detection)

---

### 2.2 Windows 10 — Victim Endpoint

**Role:** Monitored endpoint  
**Telemetry Sources:**
- Sysmon (process, network, persistence events)
- Winlogbeat (log forwarding agent)

---

### 2.3 pfSense — Network Gateway

**Role:** Firewall, DNS enforcement, network telemetry  
**Functions:**
- DNS policy enforcement
- Network egress control
- Firewall logging forwarded to SIEM

---

### 2.4 Kali Linux — Attacker

**Role:** Adversary simulation  
**Purpose:** Generate malicious traffic and endpoint activity for detection testing

---

## 3. Core Services (Ubuntu SIEM)

| Service | Port | Function |
|---------|------|----------|
| Elasticsearch | 9200 | Log storage and indexing |
| Logstash | 5044 (Beats), 514 (Syslog) | Log ingestion and normalization |
| Kibana | 5601 | Analyst interface |
| Suricata | — | Network IDS, JSON alert output |

---

## 4. Data Sources

### Endpoint Telemetry
- Windows Event Logs
- Sysmon Operational Logs (Event IDs: 1, 3, 7, 11, 13, 22)

### Network Telemetry
- pfSense firewall logs
- DNS enforcement events
- Suricata IDS alerts (JSON)

---

## 5. Ingestion Paths

```
Windows  → Winlogbeat → Logstash:5044 → Elasticsearch
pfSense  → Syslog     → Logstash:514  → Elasticsearch
Suricata → JSON logs  → Logstash      → Elasticsearch
```
