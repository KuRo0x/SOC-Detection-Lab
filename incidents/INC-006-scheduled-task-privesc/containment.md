# INC-006: Containment & Remediation

## Immediate Containment Actions

### 1. Delete the Malicious Scheduled Task
```cmd
schtasks /delete /tn "WindowsMaintenance" /f
```

### 2. Remove Proof Artifact
```cmd
del C:\Windows\Temp\privesc\proof.txt
rmdir C:\Windows\Temp\privesc
```

### 3. Audit All Scheduled Tasks for SYSTEM Execution
```cmd
schtasks /query /fo LIST /v | findstr /i "SYSTEM"
```

### 4. Review Compromised Account (from INC-003)
```cmd
net user END-Alex
net localgroup Administrators
```

### 5. Disable Compromised Account
```cmd
net user END-Alex /active:no
```

---

## Verification

After containment, verify the task no longer exists:
```cmd
schtasks /query /tn "WindowsMaintenance"
```
Expected: `ERROR: The system cannot find the file specified.`

---

## Long-Term Remediation

- Enforce **least privilege** — standard users should not be able to create tasks with `/ru SYSTEM`
- Enable **AppLocker or WDAC** policies to restrict executable paths in scheduled tasks
- Deploy the Sigma rule to production SIEM for continuous monitoring
- Review all accounts created outside of standard provisioning process (see INC-003)
