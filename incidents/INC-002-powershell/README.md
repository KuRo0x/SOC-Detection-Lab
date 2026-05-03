# INC-002 — PowerShell Shortcut Attack

## Incident Summary

| Field | Details |
|---|---|
| **Incident ID** | INC-002 |
| **Title** | Suspicious PowerShell Execution & Persistence |
| **Severity** | High |
| **Status** | Resolved |
| **Date** | 2025 (Lab) |
| **Analyst** | KuRo |

## Affected Asset

| Field | Details |
|---|---|
| **Hostname** | END-Alex |
| **OS** | Windows 10 VM |
| **User** | Standard User |
| **Network Zone** | Isolated Lab (VMnet) |
| **Logging** | Sysmon + Winlogbeat → Elastic Stack |

## Attack Summary

A user executed a disguised shortcut file which launched `cmd.exe`, which then spawned `powershell.exe` with `ExecutionPolicy Bypass` to run a payload script. The script created a marker artifact and established persistence via a Windows Run registry key.

## Execution Chain

```
explorer.exe
    ↓
cmd.exe
    ↓
powershell.exe -ExecutionPolicy Bypass -File payload.ps1
    ↓
C:\Users\Public\ir_lab_marker.txt (created)
    ↓
HKCU\Software\Microsoft\Windows\CurrentVersion\Run (persistence)
```

## MITRE ATT&CK Mapping

| Technique ID | Name | Phase |
|---|---|---|
| T1059.001 | PowerShell | Execution |
| T1059.003 | Windows Command Shell | Execution |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence |
| T1204.002 | Malicious File | Initial Access |

## Outcome

Persistence mechanism identified and documented. No outbound network activity observed. Detection rules and Sigma rule created post-incident.

## Case Files

| File | Description |
|---|---|
| `detection.md` | KQL queries used to detect the activity |
| `investigation.md` | Full investigation findings |
| `timeline.md` | Chronological event reconstruction |
| `playbook.md` | Reusable response runbook |
| `improvements.md` | Post-incident improvements |
| `evidence/` | Screenshots from Elastic/Sysmon |
