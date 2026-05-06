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

### Query 3 — Explicit Credential Use

```kql
event.code: 4648 and winlog.event_data.TargetUserName: "END-Alex"
```

**What it shows:**
- Event 4648 = Explicit credentials provided for a logon
- Perfect PtH fingerprint when combined with LogonType 3 NTLM

---

### Query 4 — PsExec Service Fingerprint

```kql
event.code: 7045 and (service.name.keyword: *UYhp* or service.name.keyword: *rsGq* or service.name.keyword: *bvsb*)
```

**What it shows:**
- Event 7045 with randomized service names from PsExec attempts

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
