# INC-008: Pass-the-Hash Lateral Movement

## Summary

| Field | Value |
|---|---|
| **Incident ID** | INC-008 |
| **Title** | Pass-the-Hash Lateral Movement via Impacket PsExec |
| **Date** | 2026-05-06 |
| **Severity** | Critical |
| **Status** | Closed |
| **Attacker** | Kali Linux — 172.16.0.5 |
| **Victim** | DESKTOP-DPU3CDQ — 172.16.0.10 |
| **Account** | END-Alex |
| **MITRE ATT&CK** | T1550.002 — Pass the Hash |

## Description

Following credential dumping in INC-007, the attacker reused the stolen NTLM hash of `END-Alex` to authenticate remotely to the victim machine via SMB without needing the plaintext password. Using `impacket-psexec`, the attacker:

1. Authenticated to `ADMIN$` using the stolen NTLM hash
2. Uploaded a remote service binary to the victim
3. Created and started a Windows service (`UYhp`) via SCM
4. Gained a remote shell running as `NT AUTHORITY\SYSTEM`

## Attack Chain

```
INC-007 (Credential Dump) → NTLM Hash Stolen → INC-008 (PtH Lateral Movement)
```

## Files

| File | Description |
|---|---|
| `detection.md` | Kibana queries and event analysis |
| `investigation.md` | Full timeline and attack reconstruction |
| `containment.md` | Containment and remediation steps |
| `iocs.md` | Indicators of compromise |
| `lessons-learned.md` | Hardening and prevention |
| `evidence/` | Screenshots and log exports |
