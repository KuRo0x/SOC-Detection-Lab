# Detection

## Detection Source
Elastic (Winlogbeat with Sysmon telemetry)

## Detection Logic
Suspicious browser download activity was identified by searching for incomplete or interrupted download artifacts commonly associated with phishing payload delivery.

### Query Used
```kql
event.original:*crdownload*
```

## What Triggered It
- `.crdownload` artifact created by Microsoft Edge (`msedge.exe`)
- `Zone.Identifier` stream observed — confirms internet-origin file
- No execution child processes detected at this stage
