# INC-007: Detection Strategy

## Detection Stack

| Component | Event ID | Role |
|-----------|----------|------|
| Sysmon | 10 | Primary — LSASS process access |
| Sysmon | 1 | Process creation (mimikatz, procdump) |
| Sysmon | 11 | File creation (lsass.dmp) |
| Windows Security | 4656 | Handle to LSASS (optional, if auditing enabled) |

---

## Kibana KQL Queries

**Primary — Malicious LSASS access only:**
```kql
event.code: "10" AND winlog.event_data.TargetImage: "*lsass.exe*" AND (winlog.event_data.SourceImage: "*mimikatz*" OR winlog.event_data.SourceImage: "*procdump*")
```

**Full attack chain correlation:**
```kql
(
  (event.code: "10" AND winlog.event_data.TargetImage: "*lsass.exe*" AND NOT winlog.event_data.SourceImage: ("C:\\Windows\\system32\\svchost.exe" OR "C:\\Windows\\system32\\wbem\\wmiprvse.exe" OR "C:\\Windows\\System32\\wininit.exe" OR "C:\\Windows\\System32\\csrss.exe"))
  OR
  (event.code: "1" AND (winlog.event_data.Image: "*mimikatz*" OR winlog.event_data.Image: "*procdump*"))
  OR
  (event.code: "11" AND winlog.event_data.TargetFilename: "*lsass.dmp*")
)
AND host.name: "desktop-dpu3cdq"
```

**All LSASS Event 10 (for baseline review):**
```kql
event.code: "10" AND winlog.event_data.TargetImage: "*lsass.exe*"
```

---

## Baseline Analysis

From 35 Event 10 documents observed targeting `lsass.exe`, the following were confirmed legitimate:

| SourceImage | GrantedAccess | Verdict |
|-------------|---------------|---------|
| C:\Windows\system32\svchost.exe | 0x1000 | ✅ Legitimate — service query |
| C:\Windows\system32\wbem\wmiprvse.exe | 0x1400 | ✅ Legitimate — WMI perf counters (CorperfmonExt.dll) |
| C:\Tools\procdump\procdump64.exe | 0x1FFFFF | 🔴 Malicious — full process access |
| C:\Tools\mimikatz\x64\mimikatz.exe | 0x1410 | 🔴 Malicious — credential read |

**Key differentiator:** Malicious tools request `0x1FFFFF` (PROCESS_ALL_ACCESS) or `0x1410` (QUERY + VM_READ). Legitimate system tools rarely exceed `0x1400`.

---

## False Positive Analysis

| Tool | Legitimate Use | How to Differentiate |
|------|----------------|---------------------|
| ProcDump | IT crash dump collection | Run from `C:\Program Files\` or `C:\Windows\`, not `C:\Tools\` |
| Task Manager | View process info | GrantedAccess = 0x1000, source = `taskmgr.exe` |
| MsMpEng.exe | AV memory scan | Signed binary from `C:\Program Files\Windows Defender\` |
| wmiprvse.exe | WMI perf collection | CallTrace contains `CorperfmonExt.dll` — distinctive |

**Lab FP rate:** 0%  
**Expected production FP rate:** 5–15% without tuning

---

## Detection Gaps

| Evasion Technique | Detected? | Reason |
|-------------------|-----------|--------|
| Direct mimikatz (disk) | ✅ Yes | Sysmon Event 1 + Event 10 |
| ProcDump memory dump | ✅ Yes | Sysmon Event 10 + Event 11 |
| comsvcs.dll MiniDump (`rundll32.exe`) | ❌ No | SourceImage looks like legit Windows tool |
| In-memory Mimikatz (PowerShell) | ⚠️ Partial | Needs PowerShell ScriptBlock logging |
| Direct syscall / unhooking | ❌ No | Bypasses Sysmon kernel callbacks |
| Task Manager dump (RDP) | ⚠️ Partial | Event 10 fires but source is `taskmgr.exe` (common FP) |
