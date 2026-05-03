# T1136.001 – Local Admin Account Creation: Full IR Case
## SOC Detection Lab | KuRo0x/SOC-Detection-Lab

> **MITRE ATT&CK:** T1136.001 – Create Account: Local Account  
> **Tactic:** Persistence  
> **Platform:** Windows  
> **Lab Date:** 2026-04-28  
> **Detection Confirmed:** 2026-05-02  
> **Analyst:** KuRo  
> **Status:** Completed ✅

---

## Table of Contents

1. [Lab Environment](#1-lab-environment)
2. [Audit Policy Configuration](#2-audit-policy-configuration)
3. [Attack Simulation](#3-attack-simulation)
4. [Windows Event Log Evidence](#4-windows-event-log-evidence)
5. [Full IR Analysis](#5-full-ir-analysis)
6. [Sigma Rule & Elastic Detection](#6-sigma-rule--elastic-detection)
7. [Gaps Found During This Lab](#7-gaps-found-during-this-lab)
8. [Recommendations](#8-recommendations)
9. [References](#9-references)

---

## 1. Lab Environment

### 1.1 Infrastructure Used

| Component | Details |
|---|---|
| Victim Machine | Windows 10/11 – DESKTOP-DPU3CDQ (standalone endpoint) |
| SIEM | Elastic Stack (ELK) – Kibana 8.x |
| Log Forwarder | Winlogbeat 8.x on victim machine |
| Elastic Index | `winlogbeat-*` |
| Attack Method | Manual – `net.exe` commands run locally on victim |

### 1.2 What We Were Testing

We simulated an attacker who already has access to a Windows endpoint (e.g., via phishing, RDP brute force, or initial exploitation) and creates a new **local administrator account** to maintain persistence. This maps to **T1136.001** in the MITRE ATT&CK framework.

---

## 2. Audit Policy Configuration

Before running the attack or ingesting logs, we first verified and configured the Windows audit policy on the victim machine to ensure relevant events would be generated.

We opened:
```
secpol.msc → Advanced Audit Policy Configuration → System Audit Policies – Local Group Policy Object
```

### 2.1 Policies We Enabled

| Category | Subcategory | Audit Setting | Event IDs Generated |
|---|---|---|---|
| Account Management | Audit User Account Management | **Success** | 4720, 4722, 4723, 4726, 4738 |
| Logon/Logoff | Audit Logon | **Success** | 4624, 4625 |
| Detailed Tracking | Audit Process Creation | **Success** | 4688 |

> **Note:** Only "Success" was enabled for this lab because we are detecting successful persistence actions. In a real SOC environment you would also enable "Failure" auditing.

### 2.2 Why These Policies Matter

- **Audit User Account Management (Success):** Generates Event 4720 when a new local account is created and Event 4732 when a member is added to a security-enabled local group. Without this, the account creation and group assignment are completely invisible.
- **Audit Logon (Success):** Generates Event 4624 every time an account logs on, allowing detection of newly created accounts being used after creation.
- **Audit Process Creation (Success):** Generates Event 4688 every time a new process starts — captures the `net.exe` commands used in the attack.

---

## 3. Attack Simulation

### 3.1 Commands Used on the Victim Machine

```cmd
:: Step 1 – Create a new local user account
net user backdoor Password123! /add

:: Step 2 – Add the new account to the local Administrators group
net localgroup administrators backdoor /add
```

> **Account name used:** `backdoor`  
> **Password used:** `Password123!`  
> **Run as:** currently logged-in user (simulating attacker who has already compromised a session)

### 3.2 What These Commands Do at the OS Level

- `net user backdoor Password123! /add` – creates a local SAM account named `backdoor`
- `net localgroup administrators backdoor /add` – assigns the `backdoor` account to the built-in `Administrators` group, granting full local admin rights

Both actions are logged by Windows Security because of the audit policies above.

---

## 4. Windows Event Log Evidence

### 4.1 Event ID 4720 – A User Account Was Created

| Field | Value | Meaning |
|---|---|---|
| `EventCode` | 4720 | User account was created |
| `TargetUserName` | `backdoor` | The new account that was created |
| `TargetDomainName` | `DESKTOP-DPU3CDQ` | Local machine – confirms local, not domain, account |
| `SubjectUserName` | The user who ran the command | The actor – must be investigated |
| `SubjectLogonId` | Logon session ID (hex) | Ties this event to a specific logon session |

### 4.2 Event ID 4732 – A Member Was Added to a Security-Enabled Local Group

| Field | Value | Meaning |
|---|---|---|
| `EventCode` | 4732 | Member added to local security group |
| `MemberName` | `backdoor` | The account added to the group |
| `MemberSid` | SID of the backdoor account | Unique identifier for cross-event correlation |
| `GroupName` | `Administrators` | The privileged group |
| `SubjectUserName` | Same actor as 4720 | Confirms same session and actor |
| `SubjectLogonId` | Same Logon Session ID as 4720 | Ties both events together |

### 4.3 Event ID 4688 – A New Process Was Created

Two 4688 events expected:

| # | `NewProcessName` | `CommandLine` |
|---|---|---|
| 1 | `C:\Windows\System32\net.exe` | `net user backdoor Password123! /add` |
| 2 | `C:\Windows\System32\net.exe` | `net localgroup administrators backdoor /add` |

### 4.4 Event ID 4624 – Successful Logon

| Field | Meaning |
|---|---|
| `TargetUserName: backdoor` | Confirms the new account was used |
| `LogonType: 2` | Interactive (local) |
| `LogonType: 10` | RemoteInteractive (RDP) |

---

## 5. Full IR Analysis

### 5.1 Attack Timeline

```
[T+0s]  4688 – cmd.exe launched by Actor
[T+1s]  4688 – net.exe: user backdoor Password123! /add
[T+2s]  4720 – Account "backdoor" created on DESKTOP-DPU3CDQ
[T+3s]  4688 – net.exe: localgroup administrators backdoor /add
[T+4s]  4732 – "backdoor" added to local group "Administrators"
[T+?s]  4624 – Logon event for "backdoor" (if used)
```

### 5.2 MITRE ATT&CK Mapping

| ATT&CK Field | Value |
|---|---|
| Tactic | Persistence (TA0003) |
| Technique | T1136 – Create Account |
| Sub-technique | T1136.001 – Local Account |
| Tool used | net.exe (LOLBIN – Living off the Land Binary) |
| Log sources | Windows Security Log |
| Key Event IDs | 4720, 4732, 4688, 4624 |

### 5.3 Triage Decision Matrix

| Indicator | Benign | Suspicious | Malicious |
|---|---|---|---|
| `SubjectUserName` is a known IT admin | ✅ | — | — |
| Matching change ticket exists | ✅ | — | — |
| Action happens during maintenance window | ✅ | — | — |
| `SubjectUserName` is a normal end user | — | ⚠️ | — |
| Account name is suspicious (`backdoor`, `temp`, `svc$`) | — | ⚠️ | 🔴 |
| 4720 and 4732 happen within seconds of each other | — | ⚠️ | 🔴 |
| Same pattern on multiple hosts in short timeframe | — | — | 🔴 |
| No change ticket, no approval, outside hours | — | ⚠️ | 🔴 |
| New account used for logon (4624) shortly after creation | — | ⚠️ | 🔴 |

### 5.4 Containment Actions

```cmd
:: Disable the account
net user backdoor /active:no

:: Remove from Administrators group
net localgroup administrators backdoor /delete

:: Optional – delete the account completely
net user backdoor /delete
```

---

## 6. Sigma Rule & Elastic Detection

### 6.1 Sigma Rule

File: `detection-engineering/sigma/t1136_local_admin.yml`

```yaml
title: T1136.001 - Local Admin Account Created and Added to Administrators
id: c022ad66-52a0-45f5-a1f4-dbb7311e1203
status: experimental
description: >
  Detects when a new local user account is created (Event 4720) and
  immediately added to the local Administrators group (Event 4732).
  This is a common persistence technique mapped to MITRE T1136.001.
author: KuRo
date: 2026/04/28
references:
  - https://attack.mitre.org/techniques/T1136/001/
  - https://github.com/KuRo0x/SOC-Detection-Lab
tags:
  - attack.persistence
  - attack.t1136.001
  - attack.t1136
  - attack.privilege_escalation
  - attack.t1078.001
logsource:
  product: windows
  service: security
detection:
  account_created:
    EventID: 4720
  added_to_admins:
    EventID: 4732
    GroupName: 'Administrators'
  condition: account_created and added_to_admins
fields:
  - EventID
  - TargetUserName
  - SubjectUserName
  - SubjectLogonId
  - GroupName
  - MemberName
falsepositives:
  - Legitimate IT administrator creating a new local admin account
  - Software installation that requires a local admin account
  - Automated provisioning scripts (should be allow-listed by SubjectUserName)
level: high
```

### 6.2 Conversion to Elastic Lucene

Converted using `sigma-cli` with `pySigma-backend-elasticsearch`:

```bash
sigma convert -t lucene -p ecs_windows \
  detection-engineering/sigma/t1136_local_admin.yml \
  -o exports/elastic/t1136_local_admin.ndjson
```

Output query:
```
winlog.channel:Security AND (event.code:4720 AND (event.code:4732 AND winlog.event_data.GroupName:Administrators))
```

> **Note:** The generated Lucene query uses AND logic between two event codes, which is logically impossible in a single event. The query was corrected to OR logic when creating the Kibana rule (see Section 6.3). This is a known limitation of the Sigma condition `account_created and added_to_admins` when targeting single-event backends.

### 6.3 Kibana Detection Rule

**Rule name:** `T1136.001 - Local Admin Account Created and Added to Administrators`

| Setting | Value |
|---|---|
| Index pattern | `winlogbeat-*` |
| Query language | KQL |
| Custom query | `event.code: "4720" OR (event.code: "4732" AND winlog.event_data.GroupName: "Administrators")` |
| Severity | High |
| Risk score | 73 |
| MITRE ATT&CK | Persistence → T1136 → T1136.001 |
| Runs every | 5 minutes |
| Look-back time | 15 minutes |

### 6.4 Detection Confirmed ✅

Rule fired successfully on **May 2, 2026 @ 18:55:08** on host `desktop-dpu3cdq`:

| Field | Value |
|---|---|
| Alert name | `T1136.001 - Local Admin Account Created and Added to Administrators` |
| Severity | High |
| Risk Score | 73 |
| Host | `desktop-dpu3cdq` |
| Timestamp | `2026-05-02T18:55:08.269Z` |

---

## 7. Gaps Found During This Lab

| # | Gap | Impact | Status |
|---|-----|--------|--------|
| 1 | Sigma rule used AND logic for 4720+4732 — a single event cannot have two event codes simultaneously | Rule never fired until corrected to OR logic | Fixed |
| 2 | `sigma-cli` failed due to SSL certificate verification error when fetching MITRE ATT&CK data | Could not convert Sigma rules without workaround | Fixed via `pip-system-certs` |
| 3 | `winlog.channel:Security` filter in generated Lucene query caused zero matches | Rule executed but returned no alerts | Fixed by simplifying query to use `event.code` only |
| 4 | Multiple orphaned test accounts (`backdoor`, `backup-admin`, `temp-admin`) left on endpoint from previous lab runs | Active accounts with local admin rights — persistence risk | Remediated manually |
| 5 | No automated containment — account deletion required manual CMD execution after alert fired | Increases dwell time in a real incident | Open — playbook needed |

---

## 8. Recommendations

1. **Implement account creation alerting early** — Alert on *any* Event 4720 regardless of group membership, not only when followed by 4732.
2. **Automate containment** — Add a Kibana alert action (webhook or script) to automatically disable newly created accounts pending review.
3. **Enforce naming conventions** — Legitimate admin accounts should follow a strict naming policy (e.g., `IT-ADM-###`). Any account not matching the pattern should auto-alert.
4. **Periodic account audits** — Schedule a weekly script that compares local accounts against an approved baseline and alerts on new entries.
5. **Allow-list known provisioning accounts** — Add `SubjectUserName` exceptions for IT provisioning scripts to reduce false positives.
6. **Validate Sigma rule query logic in Discover first** — Before creating a Kibana rule, test the query in Kibana Discover to catch AND/OR logic errors early.
7. **Implement LAPS** — Local Administrator Password Solution gives every endpoint a unique randomized local admin password, preventing credential reuse.

---

## 9. References

- MITRE ATT&CK T1136.001: https://attack.mitre.org/techniques/T1136/001/
- Windows Security Auditing: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/
- Event ID 4720: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4720
- Event ID 4732: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4732
- Event ID 4688: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4688
- Event ID 4624: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624
- Sigma Rules: https://github.com/SigmaHQ/sigma
- pySigma Elasticsearch Backend: https://github.com/SigmaHQ/pySigma-backend-elasticsearch

---

*Document generated from active lab session. All events, commands, and queries were tested and verified in a controlled lab environment on DESKTOP-DPU3CDQ.*
