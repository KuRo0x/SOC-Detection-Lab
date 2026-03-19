# SOC Runbook — Analyst Playbooks

This runbook documents the investigation workflow for alerts generated in the SOC Detection Lab.
It is written as an analyst-facing guide: what to check first, what evidence to collect, how to decide severity, and how to close or escalate.

**Scope:**
- Defensive monitoring only
- No automated response actions
- Lab environment (non-production)

---

## 1. Common Analyst Workflow (All Alerts)

### 1.1 Triage Checklist (60–120 seconds)
1. Confirm **alert type** and **MITRE technique**
2. Identify:
   - Hostname / endpoint IP
   - User (if present)
   - Process name + command line (endpoint alerts)
   - Source/destination IP/port (network alerts)
3. Determine if it is expected admin activity, lab validation, or suspicious behavior
4. Decide initial severity: **Low / Medium / High**

### 1.2 Evidence to Capture (Minimum)
- Kibana screenshot of the alert event
- Query used
- Timestamp range investigated
- Related events (process parent, network connections, registry writes)
- Analyst conclusion and reasoning

### 1.3 Time Window Guidance
- Start with **± 10 minutes** around the alert timestamp
- Expand to **± 60 minutes** if you suspect a chain of activity

---

## 2. Data Sources and Where to Look

### 2.1 Windows Endpoint Telemetry
- **Primary:** Sysmon process creation, Sysmon network connections
- **Secondary:** Windows Security logs (account changes)
- **Look for:** Parent/child process relationships, encoded command lines, connections to external IPs, persistence indicators

### 2.2 pfSense Gateway Telemetry
- **Look for:** Which host attempted traffic, destination IP, port 53 attempts, repeat attempts (beaconing)

### 2.3 Suricata IDS
- **Look for:** Signature metadata, traffic tuple (src/dst/port/proto), timing correlation with endpoint events

---

## 3. Alert Playbooks

### 3.1 Suspicious PowerShell Execution — T1059.001

**Triage Questions:**
- Is the command line encoded (`-enc`) or using `IEX` / `Invoke-Expression`?
- Is PowerShell launched by a suspicious parent (Office, browser, temp dir)?
- Are there outbound connections immediately after?

**Investigation Steps:**
1. Locate Sysmon process event for `powershell.exe`, capture full command line
2. Check parent process and user context
3. Look for follow-on events ±10 minutes: network connections, file creation

| Severity | Condition |
|----------|-----------|
| Low | Plain PowerShell, no suspicious context |
| Medium | Obfuscated indicators, unclear parent |
| High | Encoded + external callbacks / download behavior |

---

### 3.2 LOLBin Abuse — Certutil (T1105)

**Triage Questions:**
- Are flags `-urlcache` or `-split` present?
- Is a remote URL present?
- Where is the output file written?

**Investigation Steps:**
1. Find Sysmon process event for `certutil.exe`
2. Capture command line including URL and output path
3. Correlate with network connections and follow-on execution

| Severity | Condition |
|----------|-----------|
| Medium | Remote URL present (certutil downloads are rarely normal) |
| High | Followed by execution or persistence |

---

### 3.3 Registry Run Key Persistence — T1547.001

**Triage Questions:**
- Which key was modified (HKCU vs HKLM)?
- What executable is being persisted?
- Is the path suspicious (Temp, AppData\Roaming)?

**Investigation Steps:**
1. Find Sysmon registry event (Run/RunOnce paths)
2. Record: registry path, value name, value data
3. Identify the creating process
4. Check if the persisted file was recently created

| Severity | Condition |
|----------|-----------|
| Medium | Persistence attempt |
| High | Correlated with other suspicious activity |

---

### 3.4 Host & User Discovery — T1033

**Triage Questions:**
- Commands from unusual parent process?
- Many discovery commands clustered together?
- Does it follow suspicious execution?

**Investigation Steps:**
1. Identify process creation events for `whoami`, `hostname`, related commands
2. Confirm user context and parent process
3. Correlate with suspicious activity ±30 minutes

| Severity | Condition |
|----------|-----------|
| Low | Standalone, no suspicious follow-on |
| Medium | Chained with other alerts |

---

### 3.5 DNS Policy Violation — T1071.004

**Triage Questions:**
- Which host attempted outbound DNS?
- What destination DNS server?
- Is this repeated (beaconing)?

**Investigation Steps:**
1. Locate pfSense firewall deny events for port 53
2. Record: source IP, destination IP, timestamps, count
3. Check endpoint events near the same time

| Severity | Condition |
|----------|-----------|
| Medium | Default |
| High | Repeated + correlated with execution alerts |

---

### 3.6 Unauthorized Local User Creation — T1136.001

**Triage Questions:**
- Which account was created?
- Who created it?
- Was it added to privileged groups?

**Investigation Steps:**
1. Find Windows Security event for user creation
2. Check group membership changes and logon events
3. Correlate with endpoint suspicious activity

| Severity | Condition |
|----------|-----------|
| Medium | Likely lab/test but unconfirmed |
| High | Unapproved account, especially with privileged group membership |

---

## 4. Case Report Format

Use this structure when documenting an investigation:

```
- Alert Type:
- MITRE Technique:
- Time Range Investigated:
- Affected Host / User:
- Key Evidence:
- Correlated Events:
- Analyst Conclusion:
- Severity:
- Closure / Escalation Reason:
```
