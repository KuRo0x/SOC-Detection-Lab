# INC-008: Detection

## SIEM: Elastic / Kibana (winlogbeat-*)

### Query 1 — Pass-the-Hash Network Logon

```kql
event.code: 4624 and winlog.event_data.LogonType: "3" and winlog.event_data.AuthenticationPackageName: "NTLM"
```

**What it shows:**
- Event 4624 = Successful logon
- LogonType 3 = Network logon (not interactive)
- NTLM = Hash used instead of Kerberos ticket

**Result:** 43 hits on May 6, 2026 — spike at 18:20–18:26

---

### Query 2 — PsExec Service Installation

```kql
event.code: 7045
```

**What it shows:**
- Event 7045 = New service installed on the system
- PsExec installs a temporary service to execute commands remotely
- Service names are randomized (e.g., `UYhp`, `rsGq`, `bvsb`)

**Result:** Service creation events confirmed on victim at 18:35 and 18:37

---

### Query 3 — NTLM General Search

```kql
NTLM
```

**Result:** 43 documents — confirms NTLM authentication activity

---

## Key Event IDs

| Event ID | Source | Meaning |
|---|---|---|
| 4624 | Security | Successful logon |
| 7045 | System | New service installed |
| 4648 | Security | Explicit credential use |

## MITRE ATT&CK

- **T1550.002** — Use Alternate Authentication Material: Pass the Hash
- **T1569.002** — System Services: Service Execution (PsExec)
