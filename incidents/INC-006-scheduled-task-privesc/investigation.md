# INC-006: Investigation Timeline

## Timeline (UTC+1, May 4 2026)

| Timestamp | Event ID | Source | Description |
|-----------|----------|--------|-------------|
| 18:52:21.436 | Sysmon Event 1 | Sysmon | `schtasks.exe` executed by `END-Alex` with `/create /tn WindowsMaintenance /ru SYSTEM /rl HIGHEST` |
| 18:52:21.489 | Event 4698 | Windows Security | Task `\WindowsMaintenance` registered in Task Scheduler |
| 18:52:22.834 | Sysmon Event 1 | Sysmon | `schtasks.exe` executed with `/run /tn WindowsMaintenance` |
| 18:52:22.851 | Sysmon Event 1 | Sysmon | `cmd.exe` spawned as `NT AUTHORITY\SYSTEM` by Task Scheduler service |

**Total attack duration: 1.4 seconds from task creation to SYSTEM execution.**

---

## Key Findings

- **Attacker Account:** `DESKTOP-DPU3CDQ\END-Alex` (created in INC-003)
- **Malicious Task Name:** `\WindowsMaintenance` (masquerades as legitimate maintenance)
- **Payload:** `cmd.exe /c whoami > C:\Windows\Temp\privesc\proof.txt`
- **Privilege Achieved:** `NT AUTHORITY\SYSTEM`
- **Proof Artifact:** `C:\Windows\Temp\privesc\proof.txt` containing `nt authority\system`

---

## Forensic Notes

- Initial audit policy gap: Event 4698 was non-responsive prior to VM reboot. Root cause: Windows kernel audit policy requires full restart to take effect.
- Detection pivoted to Sysmon Event 1 telemetry during troubleshooting, which provided superior process-level chain of custody.
- After VM reboot with audit policy active, Event 4698 fired correctly and was confirmed in Kibana via Winlogbeat.
