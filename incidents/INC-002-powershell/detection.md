# INC-002 — Detection

## Alert Source

Manual investigation of Sysmon endpoint telemetry via Elastic SIEM.

## Detection Trigger

Suspicious PowerShell execution identified with `ExecutionPolicy Bypass` argument, spawned from `cmd.exe`.

## KQL Detection Query

```kql
winlog.event_data.ParentImage:*cmd* AND
winlog.event_data.Image:*powershell* AND
winlog.event_data.CommandLine:*ExecutionPolicy*
```

## Sigma Rule (Portable)

A Sigma rule was created to provide portable detection logic for this behavior pattern:

```yaml
title: Suspicious PowerShell Execution via CMD with Bypass
status: experimental
description: Detects PowerShell launched from cmd.exe with ExecutionPolicy Bypass
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\cmd.exe'
        Image|endswith: '\powershell.exe'
        CommandLine|contains: 'ExecutionPolicy'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1059.003
```

## Evidence

- `evidence/elastic/powershell-execution-sysmon.png` — Sysmon event showing process creation chain
- `evidence/elastic/persistence-registry-run-key.png` — Registry modification event
