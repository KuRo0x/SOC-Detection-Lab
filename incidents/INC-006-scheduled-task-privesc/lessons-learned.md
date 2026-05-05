# INC-006: Lessons Learned

## What Worked Well

- **Multi-source detection** proved resilient: when Event 4698 was unavailable, Sysmon Event 1 telemetry provided full attack chain visibility
- **Correlation query** combining 4698 + Sysmon Event 1 gave a complete picture in a single Kibana search
- **Sigma rule validation** with `sigma-cli` caught formatting issues (UUID requirement, duplicate tags) before pushing to repo
- **Attack chain continuity** between INC-003 and INC-006 demonstrates realistic post-exploitation progression

---

## What Failed Initially

| Issue | Root Cause | Fix Applied |
|-------|------------|-------------|
| Event 4698 not firing | Windows audit policy requires kernel reload (reboot) to activate | Full VM reboot forced policy to take effect |
| `sigma check` UUID error | Rule ID was a custom string, not a valid UUID v4 | Generated proper UUID with `[guid]::NewGuid()` in PowerShell |
| Duplicate tag in Sigma rule | Multiple tag edits left duplicate `attack.t1053.005` entries | Rewrote file from scratch with single clean tags block |

---

## Key Takeaways

1. **Audit policy changes require a reboot** — always reboot after `auditpol` or `secpol.msc` changes in a lab environment
2. **Never rely on a single log source** — Event 4698 alone is insufficient; Sysmon process telemetry provides deeper forensic value
3. **Always validate Sigma rules** with `sigma check` before deploying — syntax errors can silently break detection
4. **Document detection gaps** — PowerShell task creation and remote task creation variants are not covered by this rule and require separate detection logic

---

## What Happens After Privilege Escalation

In this simulation, no follow-on activity was observed after SYSTEM access was achieved. The attack was contained at the privilege escalation stage. In a real incident, an attacker with `NT AUTHORITY\SYSTEM` access would likely proceed with:

1. **Credential Harvesting** — Dump LSASS memory to obtain plaintext passwords or NTLM hashes using tools like Mimikatz or ProcDump
   - Detection: Sysmon Event 10 (Process Access) targeting `lsass.exe` from a non-system process
2. **Domain Enumeration** — Query Active Directory for high-value targets, admin accounts, and domain trusts
   - Detection: `nltest.exe /domain_trusts`, `net group "Domain Admins"` in Sysmon Event 1
3. **Lateral Movement** — Use harvested credentials to access other hosts via SMB, WMI, or PSExec
   - Detection: Event 4648 (Explicit credential use), Sysmon Event 3 (Network connections)
4. **Secondary Persistence** — Install additional backdoors beyond the scheduled task (registry Run keys, new service, additional scheduled tasks)
   - Detection: Sysmon Event 13 (Registry value set), Event 7045 (New service installed)

### Detection Gaps Identified
- No Sysmon Event 10 (Process Access) monitoring rule exists for `lsass.exe` access
- No network traffic analysis for SMB lateral movement (requires Sysmon Event 3 rules)
- No detection for secondary persistence mechanisms beyond scheduled tasks
- No LSASS protection (RunAsPPL) configured on the lab host

### Next IR Case
**INC-007:** Credential dumping via LSASS access (T1003.001) — simulating Mimikatz `sekurlsa::logonpasswords` post-SYSTEM escalation

---

## Sigma Rule Performance

**Test environment:** 1 Windows VM (DESKTOP-DPU3CDQ), 8-hour monitoring window  
**True positives:** 1 (simulated attack)  
**False positives:** 0 (lab environment has minimal legitimate SYSTEM-level scheduled tasks)

**Production concerns:**
- Enterprise patch management tools (SCCM, Tanium, Intune) regularly create SYSTEM-level scheduled tasks
- Backup agents (Veeam, Acronis) and AV products (Defender, CrowdStrike) also trigger Event 4698
- Estimated tuning time in a real enterprise: 2-3 days of log review to build a reliable exclusion list

**Recommended deployment approach:**
- Deploy in alert-only mode for 1 week before enabling auto-response
- Whitelist known-good task paths: `\Microsoft\*`, `\Google\*`, `\Adobe\*`
- Require both Event 4698 AND Sysmon Event 1 (`schtasks.exe`) correlation before triggering high-severity alert
- Validate task `<Command>` field against approved executable whitelist

---

## Baseline: Legitimate SYSTEM Scheduled Tasks

In the lab environment, the following scheduled tasks running as SYSTEM are considered legitimate and should be excluded from detection rules:

| Task Path | Owner | Purpose |
|-----------|-------|---------|
| `\Microsoft\Windows\UpdateOrchestrator\*` | Microsoft | Windows Update |
| `\Microsoft\Windows Defender\*` | Microsoft | Antivirus maintenance |
| `\Microsoft\Windows\DiskCleanup\*` | Microsoft | Disk maintenance |
| `\Microsoft\Windows\Registry\*` | Microsoft | Registry backup |
| `\Microsoft\Windows\Time Synchronization\*` | Microsoft | NTP sync |

**Detection logic refinement:** The Sigma rule should exclude tasks whose `TaskName` matches `\Microsoft\*` paths, reducing false positive rate significantly in both lab and production environments.

---

## MITRE ATT&CK Coverage After INC-006

| ID | Technique | Covered |
|----|-----------|--------|
| T1566.002 | Phishing: Spearphishing Link | ✅ INC-001 |
| T1059.001 | PowerShell | ✅ INC-002 |
| T1136.001 | Create Account: Local Account | ✅ INC-003 |
| T1110.001 | Brute Force: Password Guessing | ✅ INC-004 |
| T1595.002 | Active Scanning: Vulnerability Scanning | ✅ INC-005 |
| T1053.005 | Scheduled Task/Job | ✅ INC-006 |
| T1003.001 | OS Credential Dumping: LSASS Memory | 🔜 INC-007 |
