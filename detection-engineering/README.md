# Detection Engineering

This folder contains the detection engineering work for the KuRo SOC Detection Lab — from raw query validation to production-grade Sigma rules and EQL correlation logic.

---

## Structure

| Folder | Purpose |
|---|---|
| `sigma/` | Sigma rule development and drafts |
| `siem-detections/` | Elastic Security rule definitions (KQL, EQL, threshold) |
| `detection-validation/` | True positive and false positive test cases |
| `mitre-mapping/` | ATT&CK technique coverage tracking |
| `threat-hunting/` | Proactive hunt queries and hypotheses |

---

## Detection Lifecycle

```
Incident Observed
      ↓
Validate in Kibana Discover (KQL)
      ↓
Build Elastic Security Rule
      ↓
Convert to Sigma Rule
      ↓
Document in incidents/INC-XXX/detection.md
      ↓
Store rule in detections/sigma/
```

---

## Current Detection Coverage

| Incident | Detection Type | Status |
|---|---|---|
| INC-001 Phishing | KQL custom rule | ✅ |
| INC-002 PowerShell | KQL + Sigma | ✅ |
| INC-003 Persistence | KQL + Sigma | ✅ |
| INC-004 SMB BF | KQL custom rule | ✅ |
| INC-005 Nmap Recon | Suricata rule | ✅ |
| INC-006 Sched Task | Sigma | ✅ |
| INC-007 Cred Dump | Sigma (x2) | ✅ |
| INC-008 PTH | Sigma | ✅ |
| INC-009 SSH BF | KQL custom rules (x2) | ✅ |
