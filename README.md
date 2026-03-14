<h1 align="center">SOC Detection Lab</h1>

<p align="center">
  <b>A detection-focused Virtual Security Operations Center (vSOC) — built hands-on to simulate real SOC telemetry ingestion, detection engineering, and MITRE ATT&CK–aligned investigation.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/SIEM-ELK%20Stack-005571?style=flat-square&logo=elastic&logoColor=white" />
  <img src="https://img.shields.io/badge/IDS-Suricata-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/Endpoint-Sysmon-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/Firewall-pfSense-212121?style=flat-square" />
  <img src="https://img.shields.io/badge/Rules-Sigma-6b21a8?style=flat-square" />
  <img src="https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red?style=flat-square" />
  <img src="https://img.shields.io/badge/Automation-Python-3776AB?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square" />
</p>

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Telemetry Sources](#-telemetry--data-sources)
- [Detections](#-detections-implemented)
- [Evidence](#-evidence)
- [MITRE ATT&CK Coverage](#-mitre-attck-coverage)
- [Incident Response Cases](#-incident-response-cases)
- [Detection Engineering](#-detection-engineering)
- [Documentation](#-documentation)
- [Reviewer Quickstart](#-reviewer-quickstart)
- [Skills Demonstrated](#-skills-demonstrated)
- [Why This Lab Matters](#-why-this-lab-matters)

---

## 📝 Overview

This lab is a fully virtual SOC environment I built from scratch to practice real detection engineering, log analysis, and incident response. Every component is configured, every detection is validated against live telemetry, and every finding is documented the way a real SOC analyst would.

| Property | Detail |
|---|---|
| **Host OS** | Windows 11 |
| **Hypervisor** | VMware / VirtualBox |
| **SIEM** | ELK Stack (Elasticsearch, Logstash, Kibana) |
| **IDS/IPS** | Suricata (Ubuntu Server) |
| **Firewall** | pfSense |
| **Endpoint Monitoring** | Sysmon + Winlogbeat |
| **Detection Rules** | Sigma |
| **Framework** | MITRE ATT&CK |
| **Focus** | Blue Team · Detection Engineering · Incident Response |

---

## 🏗️ Architecture

The lab runs on an isolated virtual network (`VMnet3`) — no direct host-to-lab access. All traffic passes through pfSense before reaching the endpoint, giving a single enforced inspection point.

**Traffic Flow**
```
Kali Linux (Attacker)
        ↓
  pfSense Firewall
  + Suricata IDS/IPS
        ↓
  Windows 10 Endpoint
  (Sysmon + Winlogbeat)
        ↓
   ELK Stack (SIEM)
   Elasticsearch · Logstash · Kibana
```

**Core VMs**

| VM | OS | Role |
|---|---|---|
| Attacker | Kali Linux | Adversary simulation |
| Firewall / IDS | pfSense + Suricata | Network gateway & detection |
| Victim | Windows 10 | Monitored endpoint |
| SIEM | Ubuntu Server | ELK Stack |

**Lab Architecture Diagram**

![Architecture Diagram](https://raw.githubusercontent.com/KuRo0x/vSOC-Lab/main/architecture/architecture-diagram.png)

> 📸 *Replace with* `architecture/architecture-diagram.png` *once images are moved to this repo.*

---

## 📡 Telemetry & Data Sources

### Endpoint
- Windows Security Event Logs
- Sysmon (process execution, network activity, registry changes, DNS)
- Forwarded via **Winlogbeat** → TCP 5044 → Logstash → Elasticsearch

### Network
- pfSense firewall logs (allow/deny events)
- DNS enforcement events
- Forwarded via **Syslog** → Logstash

### IDS
- Suricata structured JSON (`eve.json`) alerts
- Protocol metadata: DNS, HTTP, TLS, connection tuples

**Key Sysmon Event IDs**

| Event ID | Description | Detection Use |
|---|---|---|
| 1 | Process Creation | Execution detection |
| 3 | Network Connection | C2 / lateral movement |
| 7 | Image Loaded | DLL injection |
| 11 | File Creation | Payload drops |
| 13 | Registry Modification | Persistence |
| 22 | DNS Query | C2 domain detection |

---

## 🚨 Detections Implemented

| # | Detection | MITRE | Data Source | Confidence |
|---|---|---|---|---|
| D-001 | Suspicious Encoded PowerShell | T1059.001 | Sysmon EID 1 | 🟢 High |
| D-002 | LOLBin Abuse: Certutil | T1105 | Sysmon EID 1 | 🟢 High |
| D-003 | Registry Run Key Persistence | T1547.001 | Sysmon EID 13 | 🟢 High |
| D-004 | Host & User Discovery | T1033 | Windows Security | 🟡 Medium |
| D-005 | DNS Policy Violation | T1071.004 | pfSense Logs | 🟢 High |
| D-006 | Unauthorized Local User Creation | T1136.001 | Windows Security | 🟢 High |

Full detection logic, reproduction steps, and analyst notes → [`docs/DETECTIONS.md`](docs/DETECTIONS.md)

---

## 📸 Evidence

Real screenshots from the running lab — every detection validated against live telemetry.

### Endpoint — PowerShell Encoded Command Detected
![PowerShell Encoded Command](https://raw.githubusercontent.com/KuRo0x/vSOC-Lab/main/evidence/endpoint/powershell-encoded-command.png)
> 📸 *Replace with* `evidence/endpoint/powershell-encoded-command.png` *once images are moved.*

### Endpoint — Sysmon Operational Events
![Sysmon Operational Events](https://raw.githubusercontent.com/KuRo0x/vSOC-Lab/main/evidence/endpoint/sysmon-operational-events.png)
> 📸 *Replace with* `evidence/endpoint/sysmon-operational-events.png` *once images are moved.*

### SIEM — Kibana Alert Fired
![Kibana Alert](https://raw.githubusercontent.com/KuRo0x/vSOC-Lab/main/evidence/siem/kibana-alert-fired.png)
> 📸 *Replace with* `evidence/siem/kibana-alert-fired.png` *once images are moved.*

### SIEM — Logstash Running & Ingesting
![Logstash Running](https://raw.githubusercontent.com/KuRo0x/vSOC-Lab/main/evidence/siem/logstash-running.png)
> 📸 *Replace with* `evidence/siem/logstash-running.png` *once images are moved.*

### Network — pfSense DNS Policy
![pfSense DNS Policy](https://raw.githubusercontent.com/KuRo0x/vSOC-Lab/main/evidence/network/01_pfsense_dns_policy.png)
> 📸 *Replace with* `evidence/network/01_pfsense_dns_policy.png` *once images are moved.*

### Network — Firewall DNS Blocks
![Firewall DNS Blocks](https://raw.githubusercontent.com/KuRo0x/vSOC-Lab/main/evidence/network/02_firewall_dns_blocks.png)
> 📸 *Replace with* `evidence/network/02_firewall_dns_blocks.png` *once images are moved.*

### IDS — Suricata eve.json Output
![Suricata EVE JSON](https://raw.githubusercontent.com/KuRo0x/vSOC-Lab/main/evidence/ids/eve-json-sample.png)
> 📸 *Replace with* `evidence/ids/eve-json-sample.png` *once images are moved.*

### IDS — Suricata Service Status
![Suricata Status](https://raw.githubusercontent.com/KuRo0x/vSOC-Lab/main/evidence/ids/suricata-status.png)
> 📸 *Replace with* `evidence/ids/suricata-status.png` *once images are moved.*

### MITRE ATT&CK — Coverage Map
![MITRE ATT&CK Map](https://raw.githubusercontent.com/KuRo0x/vSOC-Lab/main/evidence/mitre/attack-mapping.png)
> 📸 *Replace with* `evidence/mitre/attack-mapping.png` *once images are moved.*

---

## 🧠 MITRE ATT&CK Coverage

| Tactic | Technique ID | Technique Name |
|---|---|---|
| Execution | T1059.001 | PowerShell |
| Execution | T1105 | Ingress Tool Transfer |
| Persistence | T1547.001 | Registry Run Keys |
| Persistence | T1136.001 | Create Local Account |
| Discovery | T1033 | System Owner/User Discovery |
| Command & Control | T1071.004 | Application Layer Protocol: DNS |

> All mappings are based on **observed telemetry**, not assumptions. Full justification → [`docs/ATTACK_MAPPING.md`](docs/ATTACK_MAPPING.md)

---

## 🛡️ Incident Response Cases

### INC-001 — Phishing-Driven Malware Delivery Attempt
Phishing-based malware delivery detected via endpoint telemetry and contained via pfSense firewall **before payload execution**.

- Detection via Elastic (Winlogbeat + Sysmon)
- Browser download artifact investigation (`.crdownload`, `Zone.Identifier`)
- Network containment via pfSense IOC-based firewall aliases
- Full evidence-backed documentation + SOC-style playbook

📁 [`incidents/INC-001-phishing/`](incidents/INC-001-phishing/)

---

### IR-001 — PowerShell Shortcut Attack
PowerShell execution and persistence via shortcut file — investigated end-to-end with Sysmon telemetry, from initial execution through persistence mechanism identification.

📁 [`incident-response/powershell-shortcut-attack/`](incident-response/powershell-shortcut-attack/)

---

## 🔧 Detection Engineering

Sigma rules organized by MITRE ATT&CK tactic — written in standard format, portable to any compatible SIEM.

```
detection-engineering/sigma/
├── execution/        ← PowerShell abuse, Office macro spawning
├── persistence/      ← Registry run keys, scheduled tasks, service creation
└── high-fidelity/    ← Validated, low false-positive rules
```

📁 [`detection-engineering/`](detection-engineering/)

---

## 📖 Documentation

| Document | Description |
|---|---|
| [`INVENTORY.md`](docs/INVENTORY.md) | Lab components, services, and runtime status |
| [`NETWORK.md`](docs/NETWORK.md) | Network topology, IPs, and trust boundaries |
| [`PIPELINE.md`](docs/PIPELINE.md) | Log ingestion and processing design |
| [`DETECTIONS.md`](docs/DETECTIONS.md) | Detection logic, rationale, and reproduction steps |
| [`ATTACK_MAPPING.md`](docs/ATTACK_MAPPING.md) | MITRE ATT&CK justification per technique |
| [`RUNBOOK.md`](docs/RUNBOOK.md) | Per-alert analyst playbooks and triage workflow |

---

## ✅ Reviewer Quickstart

1. **Confirm data ingestion** — open Kibana, verify recent events in `winlogbeat-*`, `pfsense-*`, `suricata-*`
2. **Validate endpoint detections** — see [`docs/DETECTIONS.md`](docs/DETECTIONS.md) for exact reproduction steps
3. **Validate network detections** — trigger a DNS violation, verify pfSense deny logs arrive in Elasticsearch
4. **Review evidence** — see [`evidence/`](evidence/) for endpoint, SIEM, network, and IDS screenshots
5. **Review Sigma rules** — see [`detection-engineering/sigma/`](detection-engineering/sigma/)
6. **Review IR cases** — see [`incidents/`](incidents/) and [`incident-response/`](incident-response/)

---

## 💼 Skills Demonstrated

- ✅ Network intrusion detection (Suricata + pfSense)
- ✅ Endpoint telemetry monitoring (Sysmon + Winlogbeat)
- ✅ Centralized log analysis (ELK Stack / Kibana)
- ✅ Detection engineering (Sigma rules, behavior-based logic)
- ✅ MITRE ATT&CK mapping and coverage analysis
- ✅ Incident response documentation (INC-001, IR-001)
- ✅ SOC investigation workflow (triage → evidence → escalation)
- ✅ Phishing awareness training design
- ✅ Python automation (ATT&CK Navigator export)

---

## 🎯 Why This Lab Matters

This isn't a tutorial follow-along — it's a lab I designed, configured, broke, fixed, and documented myself. Every detection is validated against real telemetry. Every incident is documented the way it would be in a real SOC. The goal was to build something I can walk a hiring manager through and defend technically — not just show off.

---

## 🔒 Scope & Limitations

- Defensive monitoring only — no exploitation or live malware
- No automated response; containment is manually implemented and documented
- Non-production isolated lab environment
- Focus: **visibility, detection, and explainability**

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) — for educational and portfolio purposes.
