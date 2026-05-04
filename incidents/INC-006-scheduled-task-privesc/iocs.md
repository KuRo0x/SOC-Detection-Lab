# INC-006: Indicators of Compromise (IOCs)

| Type | Value | Context |
|------|-------|---------|
| Account | `DESKTOP-DPU3CDQ\END-Alex` | Compromised account used to create task (from INC-003) |
| Task Name | `\WindowsMaintenance` | Malicious scheduled task name |
| File Path | `C:\Windows\Temp\privesc\proof.txt` | Execution proof artifact written by SYSTEM |
| Process | `schtasks.exe` | Used to create and trigger malicious task |
| Process | `cmd.exe` | Spawned as NT AUTHORITY\SYSTEM by Task Scheduler |
| Registry Key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\` | Task persistence location |
| Command Line | `schtasks /create /tn "WindowsMaintenance" /tr "cmd.exe /c whoami" /sc onstart /ru SYSTEM /rl HIGHEST` | Full attack command |
| Event ID | `4698` | Windows Security — Scheduled task created |
| Event ID | `1` | Sysmon — Process creation for schtasks.exe and cmd.exe |

---

## Detection Queries

**Kibana (KQL):**
```kql
winlog.event_data.TaskName: "\\WindowsMaintenance"
```

**Kibana — Full Chain:**
```kql
(event.code: "4698" AND winlog.event_data.TaskName: "\\WindowsMaintenance") OR
(event.code: "1" AND winlog.event_data.Image: "*schtasks.exe*") OR
(event.code: "1" AND winlog.event_data.User: "NT AUTHORITY\\SYSTEM" AND winlog.event_data.Image: "*cmd.exe*")
```
