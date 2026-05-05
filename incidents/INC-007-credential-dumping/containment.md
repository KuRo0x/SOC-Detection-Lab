# INC-007: Containment & Remediation

## Immediate Actions

### 1. Remove Attack Tools
```cmd
del C:\Tools\mimikatz\x64\mimikatz.exe
del C:\Tools\procdump\procdump64.exe
del C:\Windows\Temp\lsass.dmp
```

### 2. Verify LSASS is Still Running
```cmd
tasklist | findstr lsass.exe
```
> ⚠️ Never kill lsass.exe — it will cause an immediate BSOD.

### 3. Reset Compromised Credentials
```cmd
net user END-Alex NewComplexP@ssw0rd!
net user END-Alex /active:no
```

### 4. Clear Cached Credentials
```cmd
klist purge
```

---

## Post-Incident Hardening

### Enable LSA Protection (RunAsPPL)
```registry
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
Value: RunAsPPL = 1 (DWORD)
```
```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
```
> Requires reboot. Prevents non-PPL processes from reading LSASS memory.

### Disable WDigest (Already done — confirmed null in mimikatz output)
```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
```

### Enable Credential Guard (Enterprise only)
- Requires Windows 10 Enterprise or Windows Server 2016+
- Isolates LSASS in a Hyper-V protected container
- Prevents all direct memory credential extraction

---

## Evidence Preservation Checklist

- [x] Kibana screenshots exported (Event 10, Event 1, correlation query)
- [x] Sysmon Event 10 raw JSON archived
- [x] Mimikatz output documented (credentials redacted in GitHub)
- [x] lsass.dmp hash documented — file NOT uploaded to GitHub
- [x] Account SIDs and NTLM hash logged in iocs.md

---

## Network Containment

No network containment required for this incident — local memory attack only.  
However: the stolen NTLM hash `fc9417a516bcedc3a39a05a108eda4f6` enables lateral movement.  

**Monitor for:**
- Event 4624 Logon Type 3 (network logon) from DESKTOP-DPU3CDQ
- Pass-the-Hash indicators: NTLM auth without interactive logon
- SMB connections initiated from END-Alex account to new hosts
