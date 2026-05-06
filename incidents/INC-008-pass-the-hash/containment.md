# INC-008: Containment & Remediation

## Immediate Actions

### 1. Invalidate the Stolen Hash
```cmd
net user END-Alex NewSecureP@ssw0rd2026!
```
> This changes the NTLM hash — the old one `fc9417a516bcedc3a39a05a108eda4f6` is no longer valid.

### 2. Disable the Account
```cmd
net user END-Alex /active:no
```

### 3. Remove the PsExec Service (if still present)
```cmd
sc delete UYhp
sc delete rsGq
sc delete bvsb
```

### 4. Revert UAC Registry Change
```cmd
reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /f
```

### 5. Re-enable Windows Defender Real-Time Protection
- Open Windows Security
- Re-enable Real-Time Protection
- Remove any exclusions added during the lab

---

## Post-Incident Hardening

### Block NTLM (where possible)
- Enforce Kerberos authentication in domain environments
- Use Group Policy: `Network security: Restrict NTLM`

### Enable LSA Protection (from INC-007)
```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
```

### Keep Remote UAC Enabled
```cmd
reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /f
```
> Keeps `LocalAccountTokenFilterPolicy=0` (default) — blocks remote admin share access for local accounts.

### Implement Credential Guard
- Requires Windows 10 Enterprise / Server 2016+
- Isolates NTLM hash storage from direct access
