# T1136.001 – Local Admin Account Creation
# Incident Response Case

> **MITRE ATT&CK:** [T1136.001 – Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)  
> **Author:** KuRo | SOC Detection Lab  
> **Last Updated:** 2026-04-28  
> **Status:** Complete

---

## Table of Contents

1. [Scenario Description](#1-scenario-description)
2. [Event Chain Map](#2-event-chain-map)
3. [Triage Checklist](#3-triage-checklist-first-510-minutes)
4. [Investigation Workflow](#4-investigation-workflow)
5. [Response and Containment](#5-response-and-containment-actions)
6. [Gaps Identified](#6-gaps-identified)
7. [Detection Rule Ideas](#7-detection-rule-ideas)
8. [Lessons Learned and Lab Value](#8-lessons-learned-and-lab-value)

---

## 1. Scenario Description

You are monitoring a Windows domain-joined endpoint in your SOC detection lab.  
During routine monitoring, a new local account is created on a workstation and then added to the local **Administrators** group — outside any approved change window.

You want to determine:
- Whether this was a **legitimate admin change** or an **attacker establishing persistence**.
- How to **reconstruct the full chain** using Windows event logs.
- How to **build detections and playbook steps** around this behavior.

This scenario maps to **MITRE ATT&CK T1136.001 – Create Account: Local Account**.

---

## 2. Event Chain Map (Log-Level View)

In this use case you want to see (and later detect) a chain like:

| Step | Event ID | Description | Key Fields |
|------|----------|-------------|------------|
| 1 | **4720** | A user account was created | `TargetUserName`, `SubjectUserName`, `SubjectLogonId` |
| 2 | **4732** | A member was added to a security-enabled local group | `MemberName`, `GroupName` (= Administrators), `SubjectUserName` |
| 3 | **4624** | An account was successfully logged on | `LogonType`, source IP, workstation |
| 4 | **4688** | A new process was created *(optional)* | `NewProcessName`, `ParentProcessName`, command line |

### Full Narrative Reconstruction

```
[Actor X] → launches cmd.exe / powershell.exe         (4688)
         → creates local account Y on HOST1             (4720)
         → adds Y to local Administrators group         (4732)
         → Y (or same actor) logs on to HOST1/remote    (4624)
         → additional tools/commands run afterward      (4688)
```

### Common Account Creation Methods

```cmd
# CLI
net.exe user <name> <pass> /add
net.exe localgroup administrators <name> /add

# PowerShell
New-LocalUser -Name "backdoor" -Password (ConvertTo-SecureString "P@ss" -AsPlainText -Force)
Add-LocalGroupMember -Group "Administrators" -Member "backdoor"

# GUI tools
mmc.exe  /  lusrmgr.msc
```

---

## 3. Triage Checklist (First 5–10 Minutes)

When an alert fires for **"New local admin account created"**, answer these questions immediately:

### ✅ Who created the account?
- Look at **4720** and **4732**: `SubjectUserName`, `SubjectDomainName`, `SubjectLogonId`
- Is this a known admin account? A standard service account? An ordinary user who should NOT be performing admin actions?

### ✅ Where and when?
- Hostname and IP of the endpoint
- Timestamp vs. normal working hours / maintenance window
- Does it align with a known **change ticket**?

### ✅ What is the new account?
- `TargetUserName` and `TargetSid` from **4720**
- Does the naming follow internal standards (`IT-ADM-###`, `SVC-###`)?  
  Or does it look suspicious (`test1`, `tempuser`, `sys$`)?

### ✅ Privilege level and group membership
- **4732**: Is the target group `Administrators` or another privileged group?
- Is this group membership expected for this type of account?

### ✅ Immediate logon and activity
- Look for **4624** for the new account:
  - `LogonType` → 2 (interactive), 3 (network), 10 (RDP)
  - Source IP, workstation, or user
- Scan **4688** for high-risk tools: `psexec.exe`, `wmic.exe`, `rundll32.exe`, obfuscated PowerShell

### Triage Outcome

| Outcome | Description |
|---------|-------------|
| 🟢 Clearly benign | Matches change ticket and standard behavior |
| 🟡 Benign but unconfirmed | Need IT validation |
| 🔴 Suspicious / unapproved | Likely incident — **escalate** |

---

## 4. Investigation Workflow

If triage suggests this is suspicious or unapproved, move into deeper investigation.

### Step 1 – Build a Timeline

Query for `4720`, `4732`, `4624`, `4688` around the host and time of the alert in your SIEM (Splunk, Elastic, etc.).
Sort by timestamp to produce a sequence:

```
[HH:MM:SS]  4688  → cmd.exe / powershell.exe launched
[HH:MM:SS]  4720  → New account created: TargetUserName
[HH:MM:SS]  4732  → Account added to Administrators
[HH:MM:SS]  4624  → Logon event for new account
[HH:MM:SS]  4672  → Special privileges assigned (if any)
[HH:MM:SS]  4688  → Additional processes run under new account
```

### Step 2 – Analyze Processes and Command Lines (4688)

For each suspicious **4688** event, identify:
- `NewProcessName` → e.g. `C:\Windows\System32\net.exe`
- `ParentProcessName` → e.g. `C:\Windows\System32\cmd.exe`
- Command line arguments (if auditing is enabled)

Red flags:
- [ ] Obfuscated PowerShell (`-enc`, `-nop`, `iex`)
- [ ] Batch scripts or tools dropped from unusual paths (`%TEMP%`, `C:\ProgramData`)
- [ ] Tools like `whoami`, `net`, `nltest` run immediately after account creation

### Step 3 – Check User and Host Context

**User context:**
- Does `SubjectUserName` belong to the admins group?
- Has this user performed similar operations before?
- Is their activity pattern (host, time, action type) normal?

**Host context:**
- Is this host a critical system, jump box, or normal workstation?
- Is it already involved in other alerts (malware, RDP brute force)?

**Network context:**
- RDP or SMB connections around the same time?
- Outbound connections to unusual IPs or countries?

### Step 4 – Scope the Incident

Search across the environment for:
- Same new username appearing on **multiple hosts** (scripted deployment)
- Same creator account adding local admins on **other systems**
- Similar 4720 + 4732 sequences on different hosts within a short window

This answers: **Single-host incident or lateral movement/mass persistence?**

### Step 5 – Assess Intent and Classify

| Classification | Indicators |
|----------------|------------|
| 🟢 Admin maintenance / miscommunication | Matches IT patterns; confirmed by admins/change tickets |
| 🟡 Policy violation / risky behavior | Done without approval, bad naming hygiene, no documentation |
| 🔴 Malicious activity | No change request, suspicious tools, unusual logon patterns, linked alerts |

---

## 5. Response and Containment Actions

### Containment

**Account containment:**
```powershell
# Disable the account
Disable-LocalUser -Name "<SuspiciousAccount>"

# Remove from Administrators group
Remove-LocalGroupMember -Group "Administrators" -Member "<SuspiciousAccount>"

# Delete the account
Remove-LocalUser -Name "<SuspiciousAccount>"
```

**Host containment:**
- If other IOCs are present → isolate the host via EDR or network controls
- If uncertain → apply partial restrictions + increased monitoring

### Eradication and Hardening

**Credentials:**
- Reset passwords for accounts used by the attacker or likely exposed
- Reset shared/local admin accounts that might be reused

**Persistence hunting (check all of these):**
```
□ Scheduled tasks created around the same time
□ New services or startup entries
□ Registry Run/RunOnce keys
□ Unauthorized remote access software (AnyDesk, TeamViewer, ngrok)
□ New SSH authorized_keys or WMI subscriptions
```

**Configuration hardening:**
- Apply GPOs restricting local account creation / group membership changes
- Enable strong auditing for account management events
- Deploy LAPS (Local Administrator Password Solution) for unique local admin passwords
- Consider disabling the built-in Administrator account on workstations

### Recovery and Validation

After cleanup:
```
□ Verify logging is working: 4720, 4732, 4624, 4688 all reaching SIEM
□ Monitor host and associated accounts for anomalies
□ Watch for: new abnormal logons, recurrence of similar behavior
□ Close change ticket / incident report with full timeline
```

---

## 6. Gaps Identified

| Gap Type | Description |
|----------|-------------|
| **Logging** | Not all hosts send 4720/4732/4624/4688 to the SIEM; command-line logging disabled on some hosts |
| **Correlation** | No existing content correlates account creation + group membership + logon + process |
| **Procedure** | No process for IT to document planned local account changes; no allow-list of known admin tools |
| **Awareness** | Analysts unfamiliar with these Event IDs; documentation missing or inconsistent |

> Document these gaps and address them iteratively in your SOC lab improvements.

---

## 7. Detection Rule Ideas

See companion files in `detections/` for full implementations.

### Detection 1 – Local Account Created and Added to Administrators

**Logic:**
1. Find `4720` events where a local account is created
2. Within a short window (5–10 min) on the **same host**, find `4732` where `GroupName = "Administrators"`
3. Optionally: match `MemberName` to the newly created `TargetUserName`
4. Exclude: known installation scripts, service accounts (allow-list)

### Detection 2 – Suspicious Local Admin Creation Outside Maintenance Window

Extend Detection 1 with:
- **Time condition:** outside business hours AND outside maintenance windows
- **Actor condition:** `SubjectUserName` not in authorized admin group

### Detection 3 – Abnormal Local Account Naming Patterns

**Logic:**
- `4720` where `TargetUserName` matches patterns: `temp*`, `test*`, random strings, or mimics system accounts
- Combined with `4732` into Administrators OR `4624` logon from that account

---

## 8. Lessons Learned and Lab Value

By building and practicing this case in your SOC detection lab, you:

- ✅ Learn to read and correlate key Windows Security Events: **4720, 4732, 4624, 4688**
- ✅ Practice triage thinking: *"Is this normal admin work or a backdoor?"*
- ✅ Build reusable detections and playbooks tied to **MITRE T1136.001**
- ✅ Develop scope assessment skills (single host vs. lateral movement)
- ✅ Understand persistence mechanisms and how to hunt for them

### Repo Structure for This Case

```
docs/t1136_local_admin_ir.md                    ← this file
detections/sigma/t1136_local_admin.yml          ← Sigma rule
detections/splunk/t1136_local_admin_v1.spl      ← basic SPL
detections/splunk/t1136_local_admin_v2.spl      ← advanced SPL
```

---

*Part of [SOC-Detection-Lab](https://github.com/KuRo0x/SOC-Detection-Lab) — Blue Team Portfolio by KuRo*
