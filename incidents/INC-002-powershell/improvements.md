# INC-002 — Improvements

## Detection Gaps Identified

1. **No alert existed** for PowerShell spawned from `cmd.exe` with bypass flags — detection was manual
2. **Registry persistence** was not being alerted on — Sysmon Event ID 13 was not in any detection rule
3. **Script file execution** from user Downloads directory was not flagged

## Improvements Implemented

### 1. New KQL Detection Rule

Added rule to detect PowerShell with ExecutionPolicy Bypass spawned from cmd.exe:

```kql
winlog.event_data.ParentImage:*cmd* AND
winlog.event_data.Image:*powershell* AND
winlog.event_data.CommandLine:*ExecutionPolicy*
```

### 2. Registry Persistence Alerting

Added monitoring for Run key modifications:

```kql
winlog.event_id:13 AND
winlog.event_data.TargetObject:*\CurrentVersion\Run*
```

### 3. Sigma Rule Created

Portable Sigma rule created and stored in `detections/` for reuse across SIEM platforms.

## Recommendations

- Enforce PowerShell Constrained Language Mode for standard users
- Enable Script Block Logging (Event ID 4104) to capture full script content
- Implement application whitelisting to block execution from user directories
- Alert on `reg.exe` modifying Run keys
