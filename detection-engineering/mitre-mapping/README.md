# MITRE ATT&CK Mapping

This folder tracks the lab's MITRE ATT&CK technique coverage across all incidents and detections.

---

## Current Coverage

| Tactic | ID | Technique | Sub-technique | Incident | Detection |
|---|---|---|---|---|---|
| Initial Access | T1566 | Phishing | — | INC-001 | KQL rule |
| Execution | T1059.001 | PowerShell | Command and Script Interpreter | INC-002 | KQL + Sigma |
| Persistence | T1547 | Boot/Logon Autostart | Registry Run Keys | INC-003 | KQL + Sigma |
| Credential Access | T1110 | Brute Force | Password Guessing | INC-004, INC-009 | KQL rule |
| Discovery | T1046 | Network Service Scanning | — | INC-005 | Suricata |
| Privilege Escalation | T1053 | Scheduled Task/Job | — | INC-006 | Sigma |
| Credential Access | T1003 | OS Credential Dumping | LSASS Memory | INC-007 | Sigma (x2) |
| Lateral Movement | T1550.002 | Use Alternate Auth Material | Pass-the-Hash | INC-008 | Sigma |
| Credential Access | T1110.001 | Brute Force | Password Guessing | INC-009 | KQL rule |

---

## Coverage Stats

- **Tactics covered:** 6 / 14
- **Techniques covered:** 8
- **Sub-techniques covered:** 3
- **Total detection rules:** 9 (4 Sigma + 5 KQL)

> Update this file after each new incident is documented.
