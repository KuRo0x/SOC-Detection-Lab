# Lab Inventory

This document lists the confirmed components, services, and roles present in the vSOC lab environment.  
All information is derived from live system status outputs and active configuration files.

---

## 1. Environment Overview

- Lab Type: Virtual Security Operations Center (vSOC)
- Network Mode: Isolated virtual network (VMnet3)
- Purpose: Detection engineering, log ingestion, and SOC-style analysis
- Scope: Defensive monitoring only

---

## 2. Virtual Machines

### 2.1 Ubuntu Server — SIEM Node

**Hostname:** soc-brn-ubn  
**Role:** Central SIEM, log processing, detection engine

**Installed Services (Confirmed Running):**
- Elasticsearch (search + storage)
- Logstash (log ingestion and processing)
- Kibana (visualization and analysis)
- Suricata (network intrusion detection)

**Service Manager:** systemd  
**Runtime Status:** Active (running)

---

### 2.2 Windows 10 — Endpoint

**Role:** Monitored endpoint  
**Telemetry Sources:**
- Sysmon (process, network, persistence events)
- Winlogbeat (log forwarding agent)

**Function:**
- Generates endpoint telemetry
- Simulates user and attacker activity
- Sends logs to SIEM via Logstash (Beats input)

---

### 2.3 pfSense — Network Gateway

**Role:** Firewall, DNS enforcement, network telemetry

**Functions:**
- DNS policy enforcement
- Network egress control
- Firewall logging

**Telemetry:**
- Firewall logs forwarded to SIEM
- DNS activity visibility

---

## 3. Core Services (Ubuntu SIEM)

### 3.1 Elasticsearch
- Status: Active (running)
- Function: Indexing and storage of all security events

### 3.2 Logstash
- Status: Active (running)
- Listening Port: TCP 5044 (Beats input)
- Function: Central ingestion, normalization, enrichment

### 3.3 Kibana
- Status: Active (running)
- Function: SOC analyst interface — querying, dashboards, alert review

### 3.4 Suricata
- Status: Active (running)
- Function: Network intrusion detection, structured JSON output

---

## 4. Data Sources

| Source | Type | Transport |
|---|---|---|
| Windows 10 | Endpoint logs (Sysmon, Security) | Winlogbeat → TCP 5044 |
| pfSense | Firewall + DNS logs | Syslog |
| Suricata | IDS alerts | JSON → Logstash |

---

## 5. Ingestion Paths

```
Windows  → Winlogbeat  → Logstash → Elasticsearch
pfSense  → Syslog      → Logstash → Elasticsearch
Suricata → JSON logs   → Logstash → Elasticsearch
```

---

## 6. Scope Notes

- This lab is isolated and non-production
- No offensive tooling is deployed
- Focus is on visibility, detection, and SOC workflows
