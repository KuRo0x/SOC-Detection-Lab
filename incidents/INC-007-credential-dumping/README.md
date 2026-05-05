# INC-007: Credential Dumping via LSASS Access (T1003.001)

**Incident ID:** INC-007  
**Date:** May 5, 2026  
**Analyst:** KuRo  
**Host:** DESKTOP-DPU3CDQ (172.16.0.10)  
**OS:** Windows 10 Pro (Build 19045.6466)  
**Severity:** Critical  
**Status:** Resolved — Contained in lab environment  
**Repository:** [SOC-Detection-Lab/INC-007](https://github.com/KuRo0x/SOC-Detection-Lab/tree/main/incidents/INC-007-credential-dumping)

---

## Executive Summary

Following privilege escalation in INC-006, the attacker leveraged SYSTEM-level access to dump credentials from the Local Security Authority Subsystem Service (`lsass.exe`) process. Two techniques were used:

1. **Direct memory access** via `mimikatz.exe` — extracted NTLM hash for END-Alex
2. **Memory dump creation** via `procdump64.exe` — created a 55 MB dump at `C:\Windows\Temp\lsass.dmp`

Detection was achieved through Sysmon Event 10 (Process Access) correlation with process creation telemetry. Baseline LSASS accesses from `svchost.exe` and `wmiprvse.exe` were validated and excluded from alert scope.

**MITRE ATT&CK Mapping:**
- **Primary:** T1003.001 — OS Credential Dumping: LSASS Memory
- **Chain:** T1136.001 (INC-003) → T1053.005 (INC-006) → T1003.001 (This incident)

---

## Attack Chain Context

| Stage | Incident | Technique | Description |
|-------|----------|-----------|-------------|
| 1 | INC-003 | T1136.001 | Local account END-Alex created |
| 2 | INC-006 | T1053.005 | Privilege escalation via scheduled task to SYSTEM |
| 3 | INC-007 | T1003.001 | Credential dumping via LSASS ← **YOU ARE HERE** |
| 4 | INC-008 | T1550.002 | Lateral movement via Pass-the-Hash (planned) |

---

## Attack Timeline

| Timestamp (UTC+1) | Event ID | Source | Description |
|-------------------|----------|--------|-------------|
| 2026-05-05 22:08:05 | Sysmon 1 | Sysmon | `mimikatz.exe` spawned — `C:\Tools\mimikatz\x64\mimikatz.exe` |
| 2026-05-05 22:08:55 | Sysmon 10 | Sysmon | `mimikatz.exe` → `lsass.exe` (credential extraction) |
| 2026-05-05 22:09:24 | Sysmon 1 | Sysmon | `procdump64.exe -ma lsass.exe` spawned |
| 2026-05-05 22:09:24 | Sysmon 10 | Sysmon | `procdump64.exe` → `lsass.exe` GrantedAccess: `0x1FFFFF` |
| 2026-05-05 22:09:25 | Sysmon 11 | Sysmon | `lsass.dmp` (55 MB) written to `C:\Windows\Temp\` |

---

## Credentials Compromised

| Account | Domain | NTLM Hash | Plaintext |
|---------|--------|-----------|----------|
| END-Alex | DESKTOP-DPU3CDQ | `fc9417a516bcedc3a39a05a108eda4f6` | (null — WDigest disabled) |

**SHA1:** `9d402cbb8e82adfc8de3b53fb1f41fd28313128a`  
**DPAPI:** `9d402cbb8e82adfc8de3b53fb1f41fd2`  
**Authentication ID:** 0 ; 940154 (00000000:000e587a)  
**Logon Time:** 2026-05-05 22:01:03  
**SID:** S-1-5-21-3668237714-1441189884-3754595843-1001

> WDigest returned null — plaintext credential storage was not enabled. The NTLM hash alone is sufficient for Pass-the-Hash lateral movement in INC-008.

---

## Why This Worked

1. **No RunAsPPL** — LSASS was not configured as a protected process
2. **No Credential Guard** — memory credentials accessible to SYSTEM processes
3. **Attacker had SYSTEM** — highest privilege bypasses most access controls
4. **Defender disabled** — no AV blocking of mimikatz on disk
