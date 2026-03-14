# SOC Analyst Runbook

This runbook documents the investigation workflow for alerts generated in the vSOC lab.  
It is written as an analyst-facing guide: what to check first, what evidence to collect, how to decide severity, and how to close or escalate.

---

## 1. General Triage Workflow

### Step 1 — Initial Triage (60–120 seconds)
1. Confirm alert type and MITRE technique
2. Identify: hostname, user, process + command line, source/destination IP
3. Determine: administrative activity, lab test, or suspicious behavior
4. Assign initial severity (Low / Medium / High)

### Step 2 — Evidence Collection (Minimum)
- Kibana screenshot of alert event
- Query used
- Timestamp range
- Related events (parent process, network connections, registry writes)
- Conclusion and reasoning

### Step 3 — Time Window
- Start with ±10 minutes around alert timestamp
- Expand to ±60 minutes if chained activity suspected

---

## 2. Per-Alert Playbooks

### PB-001 — Suspicious PowerShell (T1059.001)
**Triage Questions:** Is command encoded (`-enc`) or using `IEX`? Suspicious parent process? Outbound connections after execution?

| Severity | Condition |
|---|---|
| Low | Plain PowerShell, no suspicious context |
| Medium | Obfuscated, unclear parent |
| High | Encoded + external callback/download |

**Escalate if:** Encoded command + external network activity, or Office/browser spawning PowerShell.

---

### PB-002 — LOLBin Certutil (T1105)
**Triage Questions:** Are `-urlcache` / `-split` flags present? Remote URL? Where is output written?

| Severity | Condition |
|---|---|
| Medium | Remote URL present |
| High | Download followed by execution or persistence |

---

### PB-003 — Registry Run Key (T1547.001)
**Triage Questions:** HKCU vs HKLM? What executable is being persisted? Suspicious path (Temp/AppData)?

| Severity | Condition |
|---|---|
| Medium | Persistence attempt |
| High | Correlated with other suspicious activity |

---

### PB-004 — Host & User Discovery (T1033)
**Triage Questions:** Unusual parent process? Multiple discovery commands in sequence? Follows suspicious execution?

| Severity | Condition |
|---|---|
| Low | Standalone command, expected user |
| Medium | Chained with other alerts |

---

### PB-005 — DNS Policy Violation (T1071.004)
**Triage Questions:** Which host? What destination DNS server? Is it repeated (beaconing)?

| Severity | Condition |
|---|---|
| Medium | Default |
| High | Repeated + correlated with execution alerts |

---

### PB-006 — Local User Creation (T1136.001)
**Triage Questions:** Which account? Who created it? Added to privileged groups?

| Severity | Condition |
|---|---|
| Medium | Likely test but unconfirmed |
| High | Unknown account, non-admin context, privileged group |

---

## 3. Case Report Format

```
Alert Type:
MITRE Technique:
Time Range Investigated:
Affected Host / User:
Key Evidence:
Correlated Events:
Analyst Conclusion:
Severity:
Closure / Escalation Reason:
```

---

## 4. Scope Notes

- Defensive monitoring only
- No automated blocking or response automation
- Goal: defensible triage decisions based on visible telemetry
