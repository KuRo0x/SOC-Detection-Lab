<h1 align="center">SOC Detection Lab</h1>

<p align="center">
  A hands-on Virtual SOC I built to practice real detection engineering,
  log analysis, and incident response — end to end.
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

## Architecture

![Architecture Diagram](https://raw.githubusercontent.com/KuRo0x/vSOC-Lab/main/architecture/architecture-diagram.png)

| Component | Tool | Role |
|---|---|---|
| Firewall / Gateway | pfSense | Traffic control, DNS enforcement, network logging |
| IDS | Suricata | Packet inspection, signature-based alerting |
| Endpoint | Windows 10 + Sysmon | Process, registry, network, DNS telemetry |
| Log Forwarder | Winlogbeat | Ships endpoint logs to ELK via TCP 5044 |
| SIEM | ELK Stack | Log storage, processing, investigation interface |

---

## Detections

| # | Detection | MITRE | Source | Confidence |
|---|---|---|---|---|
| D-001 | Suspicious Encoded PowerShell | T1059.001 | Sysmon EID 1 | 🟢 High |
| D-002 | LOLBin Abuse: Certutil | T1105 | Sysmon EID 1 | 🟢 High |
| D-003 | Registry Run Key Persistence | T1547.001 | Sysmon EID 13 | 🟢 High |
| D-004 | Host & User Discovery | T1033 | Windows Security | 🟡 Medium |
| D-005 | DNS Policy Violation | T1071.004 | pfSense Logs | 🟢 High |
| D-006 | Unauthorized Local User Creation | T1136.001 | Windows Security | 🟢 High |

→ Full logic, reproduction steps, analyst notes: [`docs/DETECTIONS.md`](docs/DETECTIONS.md)

---

## Evidence

**Kibana — Alert Fired**
![Kibana Alert](https://raw.githubusercontent.com/KuRo0x/vSOC-Lab/main/evidence/siem/kibana-alert-fired.png)

**Endpoint — PowerShell Encoded Command Detected**
![PowerShell Detection](https://raw.githubusercontent.com/KuRo0x/vSOC-Lab/main/evidence/endpoint/powershell-encoded-command.png)

**MITRE ATT&CK — Coverage Map**
![ATT&CK Map](https://raw.githubusercontent.com/KuRo0x/vSOC-Lab/main/evidence/mitre/attack-mapping.png)

→ All evidence: [`evidence/`](evidence/)

---

## Repository Structure

```
SOC-Detection-Lab/
├── architecture/              ← Lab diagram
├── detection-engineering/
│   └── sigma/
│       ├── execution/         ← PowerShell, LOLBin rules
│       ├── persistence/       ← Registry, scheduled tasks, service rules
│       └── high-fidelity/     ← Validated low-noise rules
├── docs/
│   ├── INVENTORY.md           ← Lab components and services
│   ├── NETWORK.md             ← Topology and trust boundaries
│   ├── PIPELINE.md            ← Log ingestion design
│   ├── DETECTIONS.md          ← Detection logic and rationale
│   ├── ATTACK_MAPPING.md      ← MITRE ATT&CK justification
│   └── RUNBOOK.md             ← Analyst playbooks
├── evidence/
│   ├── endpoint/              ← Sysmon + PowerShell screenshots
│   ├── siem/                  ← Kibana + Logstash screenshots
│   ├── network/               ← pfSense DNS + firewall screenshots
│   ├── ids/                   ← Suricata eve.json + status
│   └── mitre/                 ← ATT&CK coverage map
├── incidents/
│   └── INC-001-phishing/      ← Full IR case: phishing delivery attempt
├── incident-response/
│   └── powershell-shortcut-attack/  ← IR case: PowerShell persistence
├── phishing-awareness-training/   ← SOC-validated awareness exercise
├── CHANGELOG.md
└── LICENSE
```

---

## Incident Response Cases

**INC-001 — Phishing-Driven Malware Delivery**
Detected via Sysmon + Winlogbeat before payload executed. Contained using pfSense IOC-based firewall aliases.
→ [`incidents/INC-001-phishing/`](incidents/INC-001-phishing/)

**IR-001 — PowerShell Shortcut Attack**
PowerShell execution and persistence via shortcut file, traced end-to-end through Sysmon telemetry.
→ [`incident-response/powershell-shortcut-attack/`](incident-response/powershell-shortcut-attack/)

---

## Skills Demonstrated

`Network Intrusion Detection` `Endpoint Telemetry` `SIEM Log Analysis` `Detection Engineering`
`Sigma Rules` `MITRE ATT&CK Mapping` `Incident Response` `Threat Investigation` `Python Automation`

---

## License

[MIT](LICENSE) — built for learning and portfolio purposes.
