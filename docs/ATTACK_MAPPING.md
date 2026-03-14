# MITRE ATT&CK Mapping

This document explains how each detection in the vSOC lab maps to specific MITRE ATT&CK techniques.  
Mappings are based on **observed behavior**, not tool names or assumptions.

Only techniques that are **directly evidenced by telemetry** are mapped.

---

## 1. Mapping Methodology

A detection is mapped to a technique only if:
- The observed behavior **matches the technique definition**
- The required telemetry is **explicitly captured**
- The detection logic remains valid regardless of the specific tool used

This avoids over-mapping, tool-based assumptions, and inflated coverage claims.

---

## 2. Coverage Summary

| Tactic | Technique ID | Technique Name | Detection |
|---|---|---|---|
| Execution | T1059.001 | PowerShell | D-001 |
| Execution | T1105 | Ingress Tool Transfer | D-002 |
| Persistence | T1547.001 | Registry Run Keys | D-003 |
| Persistence | T1136.001 | Create Local Account | D-006 |
| Discovery | T1033 | System Owner/User Discovery | D-004 |
| Command & Control | T1071.004 | Application Layer Protocol: DNS | D-005 |

---

## 3. Technique Justifications

### T1059.001 — PowerShell
Detects direct use of the PowerShell interpreter with encoded or expression-based execution. Full command-line arguments are captured via Sysmon EID 1. Mapping is valid regardless of payload content.

### T1105 — Ingress Tool Transfer
Detects `certutil.exe` retrieving remote files. Network destination and command-line arguments are both visible. Behavior matches ATT&CK definition regardless of intent.

### T1547.001 — Registry Run Keys
Detects modification of autorun registry paths. Registry object modification is directly captured via Sysmon EID 13. No inference required.

### T1136.001 — Create Local Account
Detects creation of new local user accounts via Windows Security Event Logs. Account creation is directly logged. Sigma rule aligns with ATT&CK definition.

### T1033 — System Owner/User Discovery
Detects execution of enumeration commands (`whoami`, `hostname`). Commands are unambiguous and behavior matches technique intent exactly.

### T1071.004 — Application Layer Protocol: DNS
Detects endpoint attempts to bypass enforced DNS resolver. DNS protocol usage is explicitly observed via pfSense deny logs. Mapping does not assume malicious payloads.

---

## 4. Intentional Gaps

The lab does **not** claim coverage for:
- Exploitation techniques
- Credential dumping
- Lateral movement
- Privilege escalation beyond account creation

These are intentionally out of scope to maintain clarity and focus on detection engineering fundamentals.

---

## 5. Scope Notes

- All mappings are derived from live lab telemetry
- No simulated or assumed behaviors are included
- Mappings are designed to be **defensible under interview questioning**
