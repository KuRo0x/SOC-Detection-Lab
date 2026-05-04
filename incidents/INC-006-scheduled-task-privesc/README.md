# INC-006: Scheduled Task Privilege Escalation

**Technique:** T1053.005 — Scheduled Task/Job  
**Severity:** High  
**Status:** Completed  
**Date:** 2026-05-04  
**Analyst:** KuRo  

---

## Attack Chain

This incident is a direct continuation of **INC-003** (Local Account Creation):

| Incident | Technique | Description |
|----------|-----------|-------------|
| INC-003 | T1136.001 | Backdoor local account created (`compromised-user`) |
| INC-006 | T1053.005 | That account used to escalate privileges via scheduled task |

---

## Summary

An attacker using the compromised account (`END-Alex`) from INC-003 created a scheduled task named `WindowsMaintenance` configured to execute `cmd.exe` as `NT AUTHORITY\SYSTEM`. The task was triggered manually and successfully spawned a SYSTEM-level process, achieving full local privilege escalation.

---

## Techniques

| ID | Name | Tactic |
|----|------|--------|
| T1053.005 | Scheduled Task/Job | Privilege Escalation, Persistence |
| T1548 | Abuse Elevation Control Mechanism | Privilege Escalation |
| T1078.001 | Valid Accounts: Local Accounts | Defense Evasion, Persistence |

---

## Evidence

| File | Description |
|------|-------------|
| `evidence/elastic/event-4698-task-created.png` | Security Event 4698 confirming task creation |
| `evidence/elastic/sysmon-schtasks-execution.png` | Sysmon Event 1 for schtasks.exe |
| `evidence/elastic/sysmon-cmd-system-execution.png` | cmd.exe spawned as NT AUTHORITY\SYSTEM |
| `evidence/elastic/correlation-query-results.png` | Full attack chain in Kibana |

---

## Related Incidents

- **INC-003:** [Persistence via Local Account Creation](../INC-003-persistence/README.md)
