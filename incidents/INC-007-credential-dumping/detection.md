# INC-007: Detection Strategy

## Detection Stack

| Component | Event ID | Role |
|-----------|----------|------|
| Sysmon | 10 | Primary — LSASS process access |
| Sysmon | 1 | Process creation (mimikatz, procdump, rundll32) |
| Sysmon | 11 | File creation (lsass.dmp, dump.bin) |
| Windows Security | 4656 | Handle to LSASS (optional, if auditing enabled) |

---

## Kibana KQL Queries

**Primary — Malicious LSASS access only:**
```kql
event.code: "10" AND winlog.event_data.TargetImage: "*lsass.exe*"
AND (winlog.event_data.SourceImage: "*mimikatz*"
  OR winlog.event_data.SourceImage: "*procdump*"
  OR winlog.event_data.SourceImage: "*rundll32*")
```

**Full attack chain correlation:**
```kql
(
  (event.code: "10" AND winlog.event_data.TargetImage: "*lsass.exe*"
   AND NOT winlog.event_data.SourceImage:
     ("*svchost.exe" OR "*wmiprvse.exe" OR "*wininit.exe" OR "*csrss.exe"))
  OR (event.code: "1" AND (winlog.event_data.Image: "*mimikatz*"
      OR winlog.event_data.Image: "*procdump*"))
  OR (event.code: "1" AND winlog.event_data.CommandLine: ("*comsvcs*" AND "*MiniDump*"))
  OR (event.code: "11" AND winlog.event_data.TargetFilename: ("*lsass.dmp*" OR "*dump.bin*"))
)
AND host.name: "desktop-dpu3cdq"
```

---

## Baseline & False Positive Analysis

**2-hour observation window (22:10–22:27, May 5 2026):**

| SourceImage | Count | GrantedAccess | Verdict |
|-------------|-------|---------------|---------|
| C:\Windows\system32\svchost.exe | ~29 | 0x1000 | ✅ Legitimate — service query |
| C:\Windows\system32\wbem\wmiprvse.exe | ~4 | 0x1400 | ✅ Legitimate — WMI perf counters |
| C:\Windows\SysWOW64\rundll32.exe | 5 | TBD | 🔴 Malicious — comsvcs MiniDump |
| C:\Windows\system32\rundll32.exe | 2 | TBD | 🔴 Malicious — comsvcs MiniDump |
| C:\Tools\procdump\procdump64.exe | 2 | 0x1FFFFF | 🔴 Malicious — ProcDump |
| C:\Tools\mimikatz\x64\mimikatz.exe | ~2 | 0x1410 | 🔴 Malicious — Mimikatz |

**Total Event 10 documents in 2hr window:** ~35+7 = ~42  
**Malicious:** ~11 (mimikatz + procdump + comsvcs rundll32)  
**Legitimate:** ~33 (svchost + wmiprvse)  
**FP Rate in lab (tuned rule v2):** 0%  
**Estimated production FP rate:** 5–10% (security tools, backup software, diagnostics)

---

## Evasion Test Results — comsvcs.dll MiniDump

**Date:** 2026-05-05 22:25–22:27  
**Technique:** T1218.011 — Signed Binary Proxy Execution: Rundll32  
**Command tested:**
```cmd
rundll32.exe C:\windows\system32\comsvcs.dll MiniDump 668 C:\Temp\dump.bin full
```

**Result:** dump.bin = 0 bytes (dump failed — privilege insufficient without SYSTEM context)  
**BUT:** Sysmon Event 10 fired 7 times from `rundll32.exe` accessing `lsass.exe`

| Sigma Rule v1 | Result |
|---------------|--------|
| lsass-access-suspicious-tool.yml v1 | ❌ MISS — rundll32.exe excluded by filter_system block |
| **lsass-access-suspicious-tool.yml v2** | **✅ CATCH — rundll32.exe explicitly re-added** |
| **comsvcs-minidump-lsass.yml (new)** | **✅ CATCH — detects comsvcs+MiniDump command line** |

**Root cause of bypass:**
The original Sigma rule excluded all processes from `C:\Windows\System32\` and `C:\Windows\SysWOW64\`.
`rundll32.exe` lives in both paths, making `comsvcs.dll MiniDump` completely invisible to v1.

**Fix applied:**
- Moved `rundll32.exe` OUT of the system path exclusion using a `filter_lolbin_exception`
- Added dedicated `comsvcs-minidump-lsass.yml` rule for command-line based detection

---

## Detection Coverage Matrix

| Technique | Sysmon Event 10 | Sigma Rule v1 | Sigma Rule v2 |
|-----------|:-----------:|:----------:|:----------:|
| mimikatz.exe (disk) | ✅ | ✅ | ✅ |
| procdump64.exe -ma lsass | ✅ | ✅ | ✅ |
| comsvcs.dll via rundll32 | ✅ | ❌ **BYPASS** | ✅ **FIXED** |
| In-memory Mimikatz (PowerShell) | ⚠️ Partial | ❌ | ❌ (needs Event 4104) |
| Direct syscalls / unhooking | ❌ | ❌ | ❌ |
| Task Manager dump (RDP) | ⚠️ Partial | ❌ | ⚠️ (taskmgr FP risk) |

---

## Sigma Rules Deployed

| File | Version | Status |
|------|---------|--------|
| lsass-access-suspicious-tool.yml | v2 (patched) | ✅ Active |
| procdump-lsass-dump.yml | v1 | ✅ Active |
| comsvcs-minidump-lsass.yml | v1 (new) | ✅ Active |
