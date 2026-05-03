# INC-002 — Containment

## Actions Taken

### 1. Registry Key Removal

The persistence Run key was identified and documented for removal:

```
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v WindowsUpdateCheck /f
```

### 2. Payload File Removal

The script file was identified at:

```
C:\Users\END-Alex\Downloads\IR-Lab\payload.ps1
```

Should be deleted and path reviewed for additional payloads.

### 3. Artifact Removal

```
del C:\Users\Public\ir_lab_marker.txt
```

### 4. PowerShell Execution Policy Review

Local execution policy should be reviewed and restricted. Constrained Language Mode should be considered for standard user accounts.

## Lab Context

This incident occurred in an isolated lab environment (VMnet). No real-world containment (network isolation, account lockout) was required. Steps above reflect what would be done in a real incident.
