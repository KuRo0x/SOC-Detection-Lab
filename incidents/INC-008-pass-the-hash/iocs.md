# INC-008: Indicators of Compromise

## Network IOCs

| Type | Value | Notes |
|---|---|---|
| Attacker IP | 172.16.0.11 | Kali Linux |
| Victim IP | 172.16.0.10 | DESKTOP-DPU3CDQ |
| Protocol | SMB (TCP 445) | Used for PsExec |
| SMB Flow | 172.16.0.11 → 172.16.0.10:445 | 28 flows logged by Suricata, 2598 bytes toserver |

## Host IOCs

| Type | Value | Notes |
|---|---|---|
| NTLM Hash | fc9417a516bcedc3a39a05a108eda4f6 | END-Alex — stolen in INC-007 (lab/simulated) |
| Account | END-Alex | Local admin on DESKTOP-DPU3CDQ |
| Service Name | UYhp | PsExec service — randomized |
| Service Name | rsGq | PsExec service — randomized |
| Service Name | bvsb | PsExec service — randomized |
| Uploaded Binary | QsfXhNpU.exe | Dropped in ADMIN$ by Impacket |
| Registry Key | LocalAccountTokenFilterPolicy=1 | Set to allow remote admin access |

## Event IOCs

| Event ID | Field | Value |
|---|---|---|
| 4624 | LogonType | 3 |
| 4624 | AuthenticationPackageName | NTLM |
| 4624 | TargetUserName | END-Alex |
| 7045 | ServiceName | UYhp / rsGq / bvsb |

## Tool

| Tool | Version | Source |
|---|---|---|
| impacket-psexec | 0.14.0.dev0 | Kali Linux / Fortra |
