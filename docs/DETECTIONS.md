# Detection Engineering

This document describes the active detections implemented in the vSOC lab.  
Each detection is based on **observable behavior**, mapped to telemetry sources, and designed to reflect real SOC alerting practices.

---

## 1. Detection Philosophy

- **Behavioral detections** over static indicators
- **Cross-source correlation** where possible
- **Explainability** for analysts
- Focus on LOLBins, execution abuse, persistence, and policy violations

---

## 2. Active Detections Summary

| Detection | MITRE | Data Source | Confidence |
|---|---|---|---|
| Suspicious Encoded PowerShell | T1059.001 | Sysmon EID 1 | 🟢 High |
| LOLBin Abuse: Certutil | T1105 | Sysmon EID 1 | 🟢 High |
| Registry Run Key Persistence | T1547.001 | Sysmon EID 13 | 🟢 High |
| Local Account Creation (Sigma) | T1136.001 | Windows Security | 🟢 High |
| Host & User Discovery | T1033 | Windows Security | 🟡 Medium |
| DNS Policy Violation | T1071.004 | pfSense Logs | 🟢 High |

---

## 3. Detection Details

### D-001 — Suspicious PowerShell Execution
**MITRE:** T1059.001  
**Source:** Sysmon EID 1

**Behavior:** Encoded commands (`-enc`), `IEX`/`Invoke-Expression`, download-and-execute patterns

**Validation:**
```powershell
powershell.exe -NoP -enc VwByAGkAdABlAC0ASABvAHMAdAAgAFYAUwBPAEMALQBMAGEAYgA=
```
Confirm alert in Kibana with full command-line context.

---

### D-002 — LOLBin Abuse: Certutil
**MITRE:** T1105  
**Source:** Sysmon EID 1

**Behavior:** `certutil.exe` with `-urlcache`, `-split`, remote URL

**Validation:**
```cmd
certutil.exe -urlcache -split -f https://example.com/
```

---

### D-003 — Registry Run Key Persistence
**MITRE:** T1547.001  
**Source:** Sysmon EID 13

**Behavior:** Modification of `HKCU/HKLM\...\CurrentVersion\Run`

**Validation:**
```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v VSOC-Lab-Test /t REG_SZ /d "C:\Windows\System32\notepad.exe" /f
```

---

### D-004 — Host & User Discovery
**MITRE:** T1033  
**Source:** Sysmon EID 1

**Behavior:** `whoami`, `hostname`, `echo %USERNAME%` — especially from suspicious parent processes

---

### D-005 — DNS Policy Violation
**MITRE:** T1071.004  
**Source:** pfSense logs

**Behavior:** Endpoint bypasses enforced DNS path, direct external DNS attempt blocked

**Validation:**
```cmd
nslookup example.com 8.8.8.8
```

---

### D-006 — Unauthorized Local User Creation
**MITRE:** T1136.001  
**Source:** Windows Security Event Logs (Sigma rule)

**Behavior:** New local account created outside expected administrative workflows

**Validation:**
```cmd
net user vsoc-test-user P@ssw0rd! /add
```

---

## 4. Analyst Workflow

1. Identify detection type and MITRE technique
2. Review command-line or network context
3. Correlate with recent endpoint or network activity
4. Assess intent (administrative vs malicious)
5. Escalate or close with justification

See [`RUNBOOK.md`](RUNBOOK.md) for per-alert playbooks.
