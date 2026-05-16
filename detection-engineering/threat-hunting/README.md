# Threat Hunting

This folder contains proactive threat hunting queries and hunt hypotheses derived from lab incidents.

---

## Active Hunt Queries

### SSH Brute Force — Burst Detection (INC-009)
```kql
message : "172.16.0.11" and message : ("Failed password" or "Accepted password" or "Invalid user")
```
**Hypothesis:** An attacker at `172.16.0.11` is performing SSH credential guessing.

---

### Suspicious PowerShell Execution (INC-002)
```kql
winlog.event_id: 1 and process.name: "powershell.exe" and process.command_line: (*-enc* or *-nop* or *bypass*)
```
**Hypothesis:** An attacker is using encoded or bypass PowerShell to evade detection.

---

### LSASS Memory Access (INC-007)
```kql
winlog.event_id: 10 and winlog.event_data.TargetImage: *lsass.exe*
```
**Hypothesis:** A process is attempting to read LSASS memory for credential dumping.

---

> Add new hunt queries here as new incidents are investigated. Include hypothesis, query, data source, and outcome.
