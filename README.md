<!-- Banner -->
<p align="center">
  <img src="docs/assets/banner.png" alt="SOC Detection Lab" width="100%" />
</p>

<h1 align="center">SOC Detection Lab</h1>

<p align="center">
  <b>A detection-focused Virtual Security Operations Center (vSOC) simulating real SOC telemetry ingestion, investigation, and MITRE ATT&CK–aligned detection engineering.</b>
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
- [MITRE ATT&CK Coverage](#-mitre-attck-coverage)
- [Incident Response Cases](#-incident-response-cases)
- [Detection Engineering](#-detection-engineering)
- [Documentation](#-documentation)
- [Reviewer Quickstart](#-reviewer-quickstart)
- [Skills Demonstrated](#-skills-demonstrated)
- [Why This Lab Matters](#-why-this-lab-matters)

---

## 📝 Overview

This lab simulates a **small enterprise SOC monitoring environment** built entirely on virtual machines. It is designed to demonstrate practical blue team skills including detection engineering, log analysis, incident investigation, and MITRE ATT&CK mapping.

| Property | Detail |
|---|---|
| **Host OS** | Windows 11 |
| **Hypervisor** | VMware / VirtualBox |
| **SIEM** | ELK Stack (Elasticsearch, Logstash, Kibana) |
| **IDS/IPS** | Suricata (on pfSense) |
| **Endpoint Monitoring** | Sysmon + Winlogbeat |
| **Detection Rules** | Sigma |
| **Framework** | MITRE ATT&CK |
| **Focus** | Blue Team · Detection Engineering · Incident Response |

---

## 🏗️ Architecture

**Network Model**
- Isolated virtual network (`VMnet3`) — no direct host-to-lab access
- Single enforced gateway (pfSense)
- All traffic inspected before reaching endpoint

**Traffic Flow**
```
Kali Linux (Attacker)
        ↓
  pfSense Firewall
  + Suricata IDS/IPS
        ↓
  Windows 10 Victim
  (Sysmon + Winlogbeat)
        ↓
   ELK Stack (SIEM)
   Elasticsearch · Logstash · Kibana
```

**Core VMs**

| VM | OS | Role |
|---|---|---|
| Attacker | Kali Linux | Adversary simulation |
| Firewall/IDS | pfSense + Suricata | Network gateway & detection |
| Victim | Windows 10 | Monitored endpoint |
| SIEM | Ubuntu Server | ELK Stack |

Architecture diagram available in [`architecture/`](architecture/)

---

## 📡 Telemetry & Data Sources

### Endpoint
- Windows Security Event Logs
- Sysmon (process execution, network activity, registry changes, DNS)
- Forwarded via **Winlogbeat** → Logstash → Elasticsearch

### Network
- pfSense firewall logs
- DNS enforcement events
- Forwarded via **Syslog**

### IDS
- Suricata structured JSON alerts
- Protocol metadata: DNS, HTTP, TLS

**Key Sysmon Event IDs Used**

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

| Detection | MITRE Technique | Data Source | Confidence |
|---|---|---|---|
| Suspicious Encoded PowerShell | T1059.001 | Sysmon EID 1 | 🟢 High |
| LOLBin Abuse: Certutil | T1105 | Sysmon EID 1 | 🟢 High |
| Registry Run Key Persistence | T1547.001 | Sysmon EID 13 | 🟢 High |
| Local Account Creation | T1136.001 | Windows Security | 🟢 High |
| Host & User Discovery | T1033 | Windows Security | 🟡 Medium |
| DNS Policy Violation | T1071.004 | pfSense Logs | 🟢 High |

Full detection logic, reproduction steps and analyst notes → [`docs/DETECTIONS.md`](docs/DETECTIONS.md)

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

> Mappings are based on **observed telemetry**, not assumptions. Full justification in [`docs/ATTACK_MAPPING.md`](docs/ATTACK_MAPPING.md)

---

## 🛡️ Incident Response Cases

### INC-001 — Phishing-Driven Malware Delivery Attempt
> Phishing-based malware delivery detected via endpoint telemetry and contained via pfSense firewall before payload execution.

**Key elements:**
- Detection via Elastic (Winlogbeat + Sysmon)
- Browser download artifact investigation (`.crdownload`, `Zone.Identifier`)
- Network containment via pfSense IOC-based firewall aliases
- Evidence-backed documentation + SOC-style playbook

📁 [`incidents/INC-001-phishing/`](incidents/INC-001-phishing/)

### IR-001 — PowerShell Shortcut Attack
> PowerShell execution and persistence via shortcut file, investigated end-to-end with Sysmon telemetry.

📁 [`incident-response/powershell-shortcut-attack/`](incident-response/powershell-shortcut-attack/)

---

## 🔧 Detection Engineering

The lab includes **Sigma rules** organized by MITRE ATT&CK tactic:

```
detection-engineering/sigma/
├── execution/        ← PowerShell, LOLBin rules
├── persistence/      ← Registry, account creation rules
└── high-fidelity/    ← Validated, low-noise rules
```

Rules are written in standard Sigma format and are portable to any compatible SIEM.

📁 [`detection-engineering/`](detection-engineering/)

---

## 📖 Documentation

| Document | Description |
|---|---|
| [`INVENTORY.md`](docs/INVENTORY.md) | Lab components and services |
| [`NETWORK.md`](docs/NETWORK.md) | Network topology and trust boundaries |
| [`PIPELINE.md`](docs/PIPELINE.md) | Log ingestion and processing design |
| [`DETECTIONS.md`](docs/DETECTIONS.md) | Detection logic and rationale |
| [`ATTACK_MAPPING.md`](docs/ATTACK_MAPPING.md) | MITRE ATT&CK justification |
| [`RUNBOOK.md`](docs/RUNBOOK.md) | Lab operation runbook |

---

## ✅ Reviewer Quickstart

Use this path to validate the lab end-to-end:

1. **Confirm data ingestion** — open Kibana and verify events in `winlogbeat-*`, `pfsense-*`, `suricata-*`
2. **Validate endpoint detections** — review [`docs/DETECTIONS.md`](docs/DETECTIONS.md) for reproduction steps
3. **Validate network detections** — trigger a DNS policy violation, verify pfSense deny logs in Elasticsearch
4. **Review evidence artifacts** — see [`evidence/`](evidence/) for endpoint, SIEM, and network screenshots
5. **Review Sigma rules** — see [`detection-engineering/sigma/`](detection-engineering/sigma/)
6. **Review incident cases** — see [`incidents/`](incidents/) for full IR documentation

---

## 💼 Skills Demonstrated

- ✅ Network intrusion detection (Suricata + pfSense)
- ✅ Endpoint telemetry monitoring (Sysmon)
- ✅ Centralized log analysis (ELK Stack)
- ✅ Detection engineering (Sigma rules)
- ✅ MITRE ATT&CK mapping and coverage analysis
- ✅ Incident response documentation
- ✅ SOC investigation workflow
- ✅ Phishing awareness training design
- ✅ Python automation (ATT&CK Navigator export)

---

## 🎯 Why This Lab Matters

This project demonstrates:
- **SOC-style thinking** — alerts are operationalized, not just triggered
- **Detection engineering fundamentals** — behavior-based, not signature-dependent
- **Explainability** — every detection is justified and reproducible
- **Clean separation of concerns** — architecture, detection, IR, and docs are independent
- **Interview-ready** — defensible under technical questioning by both technical and non-technical reviewers

---

## 🔒 Scope & Limitations

- Defensive monitoring only — no exploitation or malware deployment
- No automated response; containment is manually implemented and documented
- Non-production lab environment
- Focus is on **visibility, detection, and explainability**

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) — for educational and portfolio purposes.
