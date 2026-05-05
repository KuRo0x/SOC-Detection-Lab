# INC-007: Lessons Learned

## What Worked Well

- **Sysmon Event 10 caught both attack methods** (mimikatz and procdump) immediately
- **Baseline validation** exposed legitimate LSASS accessors (`svchost.exe`, `wmiprvse.exe`) — critical for reducing false positives
- **GrantedAccess bitmask analysis** clearly differentiated malicious from legitimate access
- **Dual-method simulation** proved detection is tool-agnostic — Event 10 fires regardless of which tool accesses LSASS
- **WDigest was already disabled** — plaintext credentials not exposed, showing a basic hardening control was in place

---

## What Didn't Work

| Gap | Detail |
|-----|--------|
| No RunAsPPL | LSASS was unprotected — trivial for SYSTEM to read memory |
| No Credential Guard | No virtualized security for credentials |
| No Sysmon Event 11 rule for .dmp | `lsass.dmp` creation was not logged (Sysmon File Create rule needed) |
| No automated response | Detection fired but no SOAR playbook to auto-kill or isolate |

---

## Detection Evasion Techniques (Not Tested)

| Technique | Would Rule Catch It? | Notes |
|-----------|---------------------|-------|
| comsvcs.dll MiniDump via rundll32 | ❌ No | `rundll32.exe` looks legitimate |
| In-memory mimikatz (Invoke-Mimikatz) | ⚠️ Partial | Needs PowerShell ScriptBlock logging (Event 4104) |
| Direct syscalls (unhooking) | ❌ No | Bypasses Sysmon kernel callbacks entirely |
| Task Manager LSASS dump over RDP | ⚠️ Partial | Event 10 fires but `taskmgr.exe` is a common FP |
| PPLKiller (bypass RunAsPPL) | ❌ No | Requires driver-level detection |

---

## Production Deployment Recommendations

1. **Deploy Sigma rules in alert-only mode** for 1 week — build whitelist of legitimate LSASS accessors
2. **Key exclusions:** `svchost.exe`, `wmiprvse.exe` (verify CallTrace contains `CorperfmonExt.dll`), `MsMpEng.exe`, `csrss.exe`
3. **Alert threshold:** ANY process from outside `C:\Windows\` or `C:\Program Files\` requesting `GrantedAccess >= 0x1410`
4. **SOAR playbook:** Auto-isolate host + force password reset on confirmed LSASS access alert

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
| T1550.002 | Pass-the-Hash | 🔜 INC-008 |

---

## Next Incident: INC-008

**Technique:** T1550.002 — Use Alternate Authentication Material: Pass-the-Hash  
**Scenario:** Use NTLM hash `fc9417a516bcedc3a39a05a108eda4f6` from INC-007 to authenticate to a second host without knowing the plaintext password  
**Detection target:** Event 4624 Logon Type 3 with NTLM, Sysmon Event 3 network connection, unusual source IP
