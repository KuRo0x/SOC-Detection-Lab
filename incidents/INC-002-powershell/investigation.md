# INC-002 — Investigation

## Process Execution Analysis

Sysmon Event ID 1 (Process Creation) showed the following chain:

```
explorer.exe
  → cmd.exe
    → powershell.exe -ExecutionPolicy Bypass -File payload.ps1
```

The PowerShell script was executed from:

```
C:\Users\END-Alex\Downloads\IR-Lab\payload.ps1
```

## Artifact Creation

During execution the script created a marker file:

```
C:\Users\Public\ir_lab_marker.txt
```

This confirmed successful payload execution.

## Persistence Mechanism

Sysmon Event ID 13 (Registry Value Set) identified a Run key persistence entry:

```
Registry Path : HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value Name    : WindowsUpdateCheck
Value Data    : powershell.exe -WindowStyle Hidden -File payload.ps1
```

Command used:

```
reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v WindowsUpdateCheck /t REG_SZ /d "powershell.exe -WindowStyle Hidden -File payload.ps1"
```

## Network Activity

No outbound network connections associated with the PowerShell process were observed. Likely due to isolated lab network configuration (VMnet).

## MITRE ATT&CK

| Technique | ID |
|---|---|
| PowerShell | T1059.001 |
| Windows Command Shell | T1059.003 |
| Registry Run Keys | T1547.001 |
