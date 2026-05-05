# INC-007: Lessons Learned

## What Worked Well

- **Multi-tool detection** proved resilient: Sysmon Event 10 caught both Mimikatz and ProcDump accessing LSASS in the same investigation window
- **Evasion testing** revealed a real bypass — `rundll32.exe` living in `C:\Windows\System32\` was excluded by the Sigma filter, allowing comsvcs MiniDump to evade detection
- **Sigma rule fix** was validated with `sigma-cli` before pushing — caught UUID format errors and invalid ATT&CK tag format
- **Attack chain continuity** from INC-006 SYSTEM escalation directly enabled credential dumping, demonstrating realistic post-exploitation progression

---

## What Failed Initially

| Issue | Root Cause | Fix Applied |
|-------|------------|-------------|
| Sigma Rule 1 missed `rundll32.exe` | `filter_system` block excluded all of `C:\Windows\System32\` | Added explicit `filter_lolbin_exception` to re-include `rundll32.exe` |
| Rule 2 CommandLine filter too strict | Sysmon logged PID instead of process name in some variants | Simplified to Image-only match on `procdump.exe` / `procdump64.exe` |
| comsvcs dump produced 0 bytes | `END-Alex` lacked sufficient privilege for `comsvcs.dll` without SYSTEM context | Confirmed SYSTEM context required — documented as privilege dependency |
| `sigma check` UUID error | Rule IDs were custom strings, not valid UUID v4 | Generated proper UUIDs with `[System.Guid]::NewGuid().ToString()` |
| Duplicate ATT&CK tags | Multiple regex edits left duplicate tag entries | Rewrote both files from scratch with clean tags block |

---

## Key Takeaways

1. **Never exclude entire system paths in Sigma rules** — `C:\Windows\System32\` contains LOLBins like `rundll32.exe` that attackers abuse; always add explicit exceptions for known-abused binaries
2. **Test evasion techniques, not just happy-path detection** — writing a rule is not enough; actively try to bypass it and document the result
3. **Always validate Sigma rules** with `sigma check` before deploying — UUID format and ATT&CK tag syntax errors are common and easy to miss
4. **WDigest disabled ≠ safe** — NTLM hash alone is sufficient for Pass-the-Hash attacks; plaintext protection does not stop lateral movement
5. **comsvcs.dll requires SYSTEM** — `rundll32 comsvcs.dll MiniDump` silently fails without SYSTEM privileges, but Sysmon still logs the attempt

---

## What Happens After Credential Dumping

With NTLM hash `fc9417a516bcedc3a39a05a108eda4f6` for `END-Alex` extracted, an attacker would proceed with:

1. **Pass-the-Hash** — Authenticate to remote hosts using the NTLM hash directly without the plaintext password
   - Detection: Event 4624 Logon Type 3, NTLM auth, no Kerberos ticket
2. **Lateral Movement** — Use `impacket-psexec` or `pth-winexe` to spawn a shell on another host
   - Detection: Sysmon Event 3 (Network connection), Event 4648 (Explicit credential use)
3. **Domain Escalation** — If a Domain Admin hash is captured, full domain compromise is possible
   - Detection: Event 4672 (Special privileges assigned), unusual admin logons
4. **Persistence** — Deploy a new backdoor on the compromised host using SYSTEM access
   - Detection: Sysmon Event 13 (Registry), Event 7045 (New service)

### Detection Gaps Identified
- No RunAsPPL configured — LSASS memory fully accessible to any SYSTEM process
- No Credential Guard — no Hyper-V isolation for credential storage
- In-memory Mimikatz via PowerShell not detected — requires Event 4104 ScriptBlock logging
- Direct syscall / unhooking techniques bypass Sysmon kernel callbacks entirely

### Next IR Case
**INC-008:** Pass-the-Hash using NTLM hash `fc9417a516bcedc3a39a05a108eda4f6` (T1550.002) — simulating lateral movement without plaintext credentials

---

## Sigma Rule Performance

**Test environment:** 1 Windows VM (DESKTOP-DPU3CDQ), 2-hour monitoring window  
**True positives:** 11 (mimikatz x1, procdump x1, rundll32 comsvcs x9)  
**False positives:** 0 (after baseline exclusions applied)

**Production concerns:**
- Security tools (CrowdStrike, Defender, Carbon Black) access LSASS legitimately — require exclusions by vendor path
- Backup agents and password managers may trigger Event 10 with elevated GrantedAccess
- Estimated tuning time in a real enterprise: 3-5 days to build a reliable exclusion list

**Recommended deployment approach:**
- Deploy Rule 1 (LSASS access) in alert-only mode for 1 week before enabling auto-response
- Whitelist known-good security tool paths before production deployment
- Rules 2 and 3 (ProcDump + comsvcs) can be deployed at high severity immediately — no legitimate use case

---

## Baseline: Legitimate LSASS Accesses

In the lab environment, the following LSASS accesses are considered legitimate and excluded from detection:

| Source Process | GrantedAccess | Purpose |
|----------------|---------------|---------|
| `svchost.exe` | `0x1000` | QUERY_LIMITED — normal Windows service queries |
| `wmiprvse.exe` | `0x1400` | WMI performance counters via `CorperfmonExt.dll` |
| `wininit.exe` | `0x1000` | System initialization |
| `csrss.exe` | `0x1000` | Client/Server Runtime Subsystem |

---

## MITRE ATT&CK Coverage After INC-007

| ID | Technique | Covered |
|----|-----------|--------|
| T1566.002 | Phishing: Spearphishing Link | ✅ INC-001 |
| T1059.001 | PowerShell | ✅ INC-002 |
| T1136.001 | Create Account: Local Account | ✅ INC-003 |
| T1110.001 | Brute Force: Password Guessing | ✅ INC-004 |
| T1595.002 | Active Scanning: Vulnerability Scanning | ✅ INC-005 |
| T1053.005 | Scheduled Task/Job | ✅ INC-006 |
| T1003.001 | OS Credential Dumping: LSASS Memory | ✅ INC-007 |
| T1550.002 | Use Alternate Authentication Material: Pass-the-Hash | 🔜 INC-008 |
