# INC-008: Indicators of Compromise

## Network IOCs

| Type | Value | Notes |
|---|---|---|
| Attacker IP | 172.16.0.5 | Kali Linux |
| Victim IP | 172.16.0.10 | DESKTOP-DPU3CDQ |
| Protocol | SMB (TCP 445) | Used for PsExec |

## Host IOCs

| Type | Value | Notes |
|---|---|---|
| NTLM Hash | fc9417a516bcedc3a39a05a108eda4f6 | END-Alex — stolen in INC-007 |
| Account | END-Alex | Domain: DESKTOP-DPU3CDQ |
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
