# INC-006: Indicators of Compromise (IOCs)

## Subject Account
| Field | Value |
|-------|-------|
| Account Name | END-Alex |
| Account Domain | DESKTOP-DPU3CDQ |
| User SID | S-1-5-21-3668237714-1441189884-3754595843-1001 |
| Logon ID | 0x7C51F |
| Logon GUID | {67b4a487-dcaf-69f8-1fc5-070000000000} |

---

## Malicious Scheduled Task (Event 4698)
| Field | Value |
|-------|-------|
| Task Name | \WindowsMaintenance |
| Task Author | DESKTOP-DPU3CDQ\END-Alex |
| Task URI | \WindowsMaintenance |
| Run As | S-1-5-18 (NT AUTHORITY\SYSTEM) |
| Run Level | HighestAvailable |
| Trigger | BootTrigger |
| Command | cmd.exe |
| Arguments | /c whoami > C:\Windows\Temp\proof.txt |
| Created | 2026-05-04T18:52:21 |
| Client Process ID | 6928 |
| Parent Process ID | 7260 |
| Winlog Record ID | 39961 |
| Activity ID | {a32c14e7-dbee-0001-5a16-2ca3eedbdc01} |

---

## schtasks.exe Process (Sysmon Event 1 - /run)
| Field | Value |
|-------|-------|
| Image | C:\Windows\System32\schtasks.exe |
| CommandLine | schtasks /run /tn "WindowsMaintenance" |
| ProcessGuid | {67b4a487-dcd6-69f8-a000-000000005600} |
| ProcessId | 840 |
| ParentImage | C:\Windows\System32\cmd.exe |
| ParentCommandLine | "C:\Windows\system32\cmd.exe" |
| ParentProcessGuid | {67b4a487-dcbf-69f8-8700-000000005600} |
| ParentProcessId | 7260 |
| ParentUser | DESKTOP-DPU3CDQ\END-Alex |
| IntegrityLevel | High |
| FileVersion | 10.0.19041.5965 |
| MD5 | 2C400322E4F96C1FEDB0F890C7668C92 |
| SHA256 | 2327E073DCF25AE03DC851EA0F3414980D3168FA959F42C5F77BE1381AE6C41D |
| IMPHASH | 7C296BC1AA0738F0783F000C5982A642 |

---

## Host Context
| Field | Value |
|-------|-------|
| Hostname | DESKTOP-DPU3CDQ |
| IP Address | 172.16.0.10 |
| MAC Address | 00-0C-29-E3-CC-CD |
| OS | Windows 10 Pro (Build 19045.6466) |
| Host ID | 67b4a487-c515-4e33-bec4-004100480ab7 |
| Elasticsearch Index | winlogbeat-2026.05.04 |

---

## Artifact
| File | Content |
|------|---------|
| C:\Windows\Temp\proof.txt | nt authority\system |

---

## Detection Queries

**Kibana (KQL) — Task Name:**
```kql
winlog.event_data.TaskName: "\\WindowsMaintenance"
```

**Kibana — Full Attack Chain:**
```kql
(event.code: "4698" AND winlog.event_data.TaskName: "\\WindowsMaintenance") OR
(event.code: "1" AND winlog.event_data.Image: "C:\\Windows\\System32\\schtasks.exe") OR
(event.code: "1" AND winlog.event_data.User: "NT AUTHORITY\\SYSTEM" AND winlog.event_data.Image: "C:\\Windows\\System32\\cmd.exe")
```
