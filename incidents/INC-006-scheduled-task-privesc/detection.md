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
(event.code: "1" AND winlog.event_data.Image: "C:\\Windows\\System32\\schtasks.exe") OR
(event.code: "1" AND winlog.event_data.Image: "C:\\Windows\\System32\\cmd.exe" AND winlog.event_data.User: "NT AUTHORITY\\SYSTEM")
```

**Results:** 6 documents covering the full attack chain from task creation to SYSTEM execution.

---

## Individual Queries

**Detect all schtasks.exe executions:**
```kql
event.code: "1" AND winlog.event_data.Image: "C:\\Windows\\System32\\schtasks.exe"
```

**Detect task creation only:**
```kql
event.code: "1" AND winlog.event_data.Image: "C:\\Windows\\System32\\schtasks.exe" AND winlog.event_data.CommandLine: *"/create"*
```

**Detect SYSTEM cmd.exe (post-escalation):**
```kql
event.code: "1" AND winlog.event_data.Image: "C:\\Windows\\System32\\cmd.exe" AND winlog.event_data.User: "NT AUTHORITY\\SYSTEM"
```

**Detect Event 4698 by task name:**
```kql
event.code: "4698" AND winlog.event_data.TaskName: "\\WindowsMaintenance"
```

---

## Sigma Rule

Sigma rule location: [`detections/sigma/INC-006_t1053_scheduled-task-privesc.yml`](../../detections/sigma/INC-006_t1053_scheduled-task-privesc.yml)

**Rule Logic:**
- Detects `schtasks.exe` with `/create` and `/ru SYSTEM` flags
- Filters for non-standard payload paths (`Temp`, `Users`, `ProgramData`)
- Excludes legitimate system paths (`System32`, `Program Files`)
- Validated with `sigma check` — 0 errors, 0 issues

**Performance (lab environment):**
- True Positives: 1
- False Positives: 0
- Note: Low FP rate is expected in a single-VM lab. Production environments with SCCM, Tanium, or enterprise patch tools will require tuning.

---

## Baseline Analysis

To distinguish malicious scheduled tasks from legitimate ones, the following query was used to enumerate all SYSTEM-level tasks in the environment:

```kql
event.code: "4698"
```

**Legitimate SYSTEM scheduled tasks observed in this environment:**

| Task Path | Owner | Purpose |
|-----------|-------|---------|
| `\Microsoft\Windows\UpdateOrchestrator\*` | Microsoft | Windows Update |
| `\Microsoft\Windows Defender\*` | Microsoft | Antivirus maintenance |
| `\Microsoft\Windows\DiskCleanup\*` | Microsoft | Disk maintenance |
| `\Microsoft\Windows\Registry\*` | Microsoft | Registry backup |
| `\Microsoft\Windows\Time Synchronization\*` | Microsoft | NTP sync |

**Why `\WindowsMaintenance` is malicious:**
- Task path is at root level (`\`) not under `\Microsoft\*`
- Author is a standard user account (`END-Alex`), not SYSTEM or a trusted service
- Trigger is `BootTrigger` — runs at every boot, a common persistence mechanism
- Command is `cmd.exe` with output redirection to `C:\Windows\Temp\` — non-standard for legitimate maintenance
- `RunLevel` is `HighestAvailable` set by a non-admin context account

**Detection logic refinement:**
Excluding tasks matching `\Microsoft\*` from the Sigma rule reduces false positive rate significantly. Additional exclusions for `\Google\*`, `\Adobe\*`, and enterprise tooling paths should be added in production deployments.

---

## Detection Gaps Identified

- **Remote task creation** via `schtasks /s` (lateral movement variant) requires additional network-level monitoring
- **PowerShell-based task creation** (`Register-ScheduledTask`) produces different telemetry not covered by this rule
- **Encoded payloads** in task actions can bypass path-based detection logic
- **LSASS access** post-escalation is not monitored (no Sysmon Event 10 rule exists)
- **Lateral movement** via SMB/WMI after SYSTEM acquisition is not covered
