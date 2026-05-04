# INC-006: Detection Strategy

## Log Sources Used

| Source | Event ID | Description |
|--------|----------|-------------|
| Windows Security Log | 4698 | Scheduled task was created |
| Sysmon | Event 1 | Process creation (schtasks.exe) |
| Sysmon | Event 1 | Process creation (cmd.exe as SYSTEM) |

---

## Kibana Correlation Query

The following KQL query surfaces the full attack chain in a single search:

```kql
(event.code: "4698" AND winlog.event_data.TaskName: "\\WindowsMaintenance") OR
(event.code: "1" AND winlog.event_data.Image: "*schtasks.exe*") OR
(event.code: "1" AND winlog.event_data.Image: "*cmd.exe*" AND winlog.event_data.User: "NT AUTHORITY\\SYSTEM")
```

**Results:** 6 documents covering the full attack chain from task creation to SYSTEM execution.

---

## Sigma Rule

Sigma rule location: [`detections/sigma/INC-006_t1053_scheduled-task-privesc.yml`](../../detections/sigma/INC-006_t1053_scheduled-task-privesc.yml)

**Rule Logic:**
- Detects `schtasks.exe` with `/create` and `/ru SYSTEM` flags
- Filters for non-standard payload paths (`Temp`, `Users`, `ProgramData`)
- Excludes legitimate system paths (`System32`, `Program Files`)
- Validated with `sigma check` — 0 errors, 0 issues

---

## Detection Gaps Identified

- **Remote task creation** via `schtasks /s` (lateral movement variant) requires additional network-level monitoring
- **PowerShell-based task creation** (`Register-ScheduledTask`) produces different telemetry not covered by this rule
- **Encoded payloads** in task actions can bypass path-based detection logic
