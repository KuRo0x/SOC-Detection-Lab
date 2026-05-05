# INC-007: Indicators of Compromise

## File Artifacts

| File | Path | Description |
|------|------|-------------|
| mimikatz.exe | C:\Tools\mimikatz\x64\mimikatz.exe | Credential dumping tool |
| procdump64.exe | C:\Tools\procdump\procdump64.exe | Sysinternals tool abused for LSASS dump |
| lsass.dmp | C:\Windows\Temp\lsass.dmp | 55 MB LSASS memory dump |

---

## Compromised Credentials

| Account | Domain | SID | NTLM Hash |
|---------|--------|-----|----------|
| END-Alex | DESKTOP-DPU3CDQ | S-1-5-21-3668237714-1441189884-3754595843-1001 | fc9417a516bcedc3a39a05a108eda4f6 |

**SHA1:** 9d402cbb8e82adfc8de3b53fb1f41fd28313128a  
**DPAPI:** 9d402cbb8e82adfc8de3b53fb1f41fd2  
**Plaintext:** (null) — WDigest disabled ✅

---

## Process Artifacts — ProcDump Event 10

| Field | Value |
|-------|-------|
| SourceImage | C:\Tools\procdump\procdump64.exe |
| SourceProcessGUID | {67b4a487-5c84-69fa-8102-000000005700} |
| SourceProcessId | 2616 |
| SourceThreadId | 7552 |
| SourceUser | DESKTOP-DPU3CDQ\END-Alex |
| TargetImage | C:\Windows\system32\lsass.exe |
| TargetProcessGUID | {67b4a487-4bf5-69fa-0c00-000000005700} |
| TargetProcessId | 668 |
| TargetUser | NT AUTHORITY\SYSTEM |
| GrantedAccess | 0x1FFFFF |
| UtcTime | 2026-05-05 21:09:24.888 |
| Winlog Record ID | 71967 |
| Elasticsearch Index | winlogbeat-2026.05.05 |

---

## Baseline IOCs (Legitimate — Excluded)

| SourceImage | GrantedAccess | Verdict |
|-------------|---------------|---------|
| C:\Windows\system32\svchost.exe | 0x1000 | ✅ Legitimate |
| C:\Windows\system32\wbem\wmiprvse.exe | 0x1400 | ✅ Legitimate |

---

## Network Indicators

*None — this is a local memory attack. No C2 communication observed.*  
*Lateral movement using stolen credentials will be tracked in INC-008.*
