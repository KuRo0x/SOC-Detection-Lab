# INC-007: Investigation Notes

## LSASS Process Details (Target)

| Field | Value |
|-------|-------|
| Process Name | lsass.exe |
| PID | 668 |
| ProcessGUID | {67b4a487-4bf5-69fa-0c00-000000005700} |
| User | NT AUTHORITY\SYSTEM |
| Protected | No (RunAsPPL not enabled) |

---

## Sysmon Event 10 — ProcDump Access (Malicious)

| Field | Value |
|-------|-------|
| UtcTime | 2026-05-05 21:09:24.888 |
| SourceImage | C:\Tools\procdump\procdump64.exe |
| SourceProcessGUID | {67b4a487-5c84-69fa-8102-000000005700} |
| SourceProcessId | 2616 |
| SourceThreadId | 7552 |
| SourceUser | DESKTOP-DPU3CDQ\END-Alex |
| TargetImage | C:\Windows\system32\lsass.exe |
| TargetProcessGUID | {67b4a487-4bf5-69fa-0c00-000000005700} |
| TargetProcessId | 668 |
| TargetUser | NT AUTHORITY\SYSTEM |
| GrantedAccess | 0x1FFFFF (PROCESS_ALL_ACCESS) |
| Winlog Record ID | 71967 |
| Elasticsearch Index | winlogbeat-2026.05.05 |

**CallTrace:**
```
ntdll.dll+9da64 | ntdll.dll+d793a | KERNEL32.DLL+1e20c | KERNEL32.DLL+2921e |
dbgcore.DLL+e681 | dbgcore.DLL+1d3d5 | dbgcore.DLL+16e45 | dbgcore.DLL+63ee |
dbgcore.DLL+6ebb | procdump64.exe+15539 | procdump64.exe+14fba |
procdump64.exe+14cba | procdump64.exe+14860 | KERNEL32.DLL+17374 | ntdll.dll+4cc91
```

> The CallTrace shows `dbgcore.DLL` — Microsoft's debug core library — invoked directly from `procdump64.exe`. This is the legitimate LSASS dump code path, but initiated by a non-system tool from `C:\Tools\`, which is the malicious indicator.

---

## Baseline LSASS Accesses (Legitimate — Excluded)

### svchost.exe
| Field | Value |
|-------|-------|
| SourceImage | C:\Windows\system32\svchost.exe |
| SourceProcessId | 780 |
| GrantedAccess | 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION) |
| UtcTime | 2026-05-05 21:11:56.575 |
| Winlog Record ID | 71977 |

### wmiprvse.exe
| Field | Value |
|-------|-------|
| SourceImage | C:\Windows\system32\wbem\wmiprvse.exe |
| SourceProcessId | 3392 |
| GrantedAccess | 0x1400 (PROCESS_QUERY_INFORMATION + PROCESS_VM_READ) |
| UtcTime | 2026-05-05 21:11:55.395 |
| Winlog Record ID | 71975 |

> `wmiprvse.exe` with `0x1400` looks suspicious but is legitimate WMI performance counter collection via `CorperfmonExt.dll`. This is a common false positive source in production environments.

---

## GrantedAccess Bitmask Analysis

| Process | GrantedAccess | Meaning | Verdict |
|---------|---------------|---------|--------|
| procdump64.exe | 0x1FFFFF | PROCESS_ALL_ACCESS — full memory read/write | 🔴 Malicious |
| wmiprvse.exe | 0x1400 | QUERY_INFORMATION + VM_READ | 🟡 Suspicious (legitimate) |
| svchost.exe | 0x1000 | QUERY_LIMITED_INFORMATION only | 🟢 Legitimate |

---

## Mimikatz Output (Evidence)

```
Authentication Id : 0 ; 940154 (00000000:000e587a)
Session           : Interactive from 1
User Name         : END-Alex
Domain            : DESKTOP-DPU3CDQ
Logon Server      : DESKTOP-DPU3CDQ
Logon Time        : 5/5/2026 9:01:03 PM
SID               : S-1-5-21-3668237714-1441189884-3754595843-1001
  msv :
   [00000003] Primary
   * Username : END-Alex
   * Domain   : DESKTOP-DPU3CDQ
   * NTLM     : fc9417a516bcedc3a39a05a108eda4f6
   * SHA1     : 9d402cbb8e82adfc8de3b53fb1f41fd28313128a
   * DPAPI    : 9d402cbb8e82adfc8de3b53fb1f41fd2
  wdigest :
   * Username : END-Alex
   * Domain   : DESKTOP-DPU3CDQ
   * Password : (null)
  kerberos :
   * Username : END-Alex
   * Domain   : DESKTOP-DPU3CDQ
   * Password : (null)
```

---

## Host Context

| Field | Value |
|-------|-------|
| Hostname | DESKTOP-DPU3CDQ |
| IP | 172.16.0.10 |
| MAC | 00-0C-29-E3-CC-CD |
| OS | Windows 10 Pro (Build 19045.6466) |
| Host ID | 67b4a487-c515-4e33-bec4-004100480ab7 |
| Winlogbeat Agent | e9a2f7fe-41b4-4cae-8f6e-58cb3668b2a2 |
| Elasticsearch Index | winlogbeat-2026.05.05 |
