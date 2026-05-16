# Investigation Methodology

This document describes the analyst investigation workflow used in the KuRo SOC Detection Lab — from alert triage to incident closure.

---

## Investigation Workflow

```
1. Alert fires in Kibana → Security → Alerts
        ↓
2. Triage: Is this a true positive or false positive?
        ↓
3. Pivot to Kibana Discover — expand the time window
        ↓
4. Build a timeline: What happened before and after?
        ↓
5. Identify source IP, victim host, user account, technique
        ↓
6. Cross-correlate across log sources (Sysmon + auth.log + Suricata)
        ↓
7. Confirm IOCs: attacker IP, filename, hash, registry key
        ↓
8. Document findings in investigation.md
        ↓
9. Escalate or contain based on severity
        ↓
10. Write lessons-learned.md and close the incident
```

---

## Key Kibana Queries per Scenario

### SSH Brute Force
```kql
host.name : "ubuntu-victim" and message : "Failed password for" and message : "172.16.0.11"
```

### PowerShell Execution
```kql
winlog.event_id : 1 and process.name : "powershell.exe"
```

### LSASS Access
```kql
winlog.event_id : 10 and winlog.event_data.TargetImage : *lsass.exe*
```

### Pass-the-Hash (EID 4624 Logon Type 3)
```kql
winlog.event_id : 4624 and winlog.event_data.LogonType : 3 and winlog.event_data.AuthenticationPackageName : NTLM
```

---

## Incident Severity Classification

| Severity | Criteria | Response Time |
|---|---|---|
| Critical | Active credential dumping, lateral movement, data exfil | Immediate |
| High | Successful brute force, privilege escalation | < 1 hour |
| Medium | Failed brute force burst, suspicious process | < 4 hours |
| Low | Single failed login, recon scan | Next review cycle |
