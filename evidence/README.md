# Evidence

This folder is the top-level evidence store for the KuRo SOC Detection Lab.  
Each incident has its own `evidence/` subfolder inside `incidents/INC-XXX-<name>/evidence/`.

---

## Evidence Standards

| Type | Format | Naming |
|---|---|---|
| Kibana screenshots | `.png` | `kibana-<view>-<date>.png` |
| Terminal output | `.png` or `.txt` | `terminal-<tool>-<date>.png` |
| Log exports | `.json` or `.log` | `<source>-export-<date>.log` |
| Packet captures | `.pcap` | `<attack>-<date>.pcap` |

---

## Per-Incident Evidence Location

| Incident | Evidence Folder |
|---|---|
| INC-001 | [`incidents/INC-001-phishing/evidence/`](../incidents/INC-001-phishing/) |
| INC-002 | [`incidents/INC-002-powershell/evidence/`](../incidents/INC-002-powershell/) |
| INC-003 | [`incidents/INC-003-persistence/evidence/`](../incidents/INC-003-persistence/) |
| INC-004 | [`incidents/INC-004-smb-bruteforce/evidence/`](../incidents/INC-004-smb-bruteforce/) |
| INC-005 | [`incidents/INC-005-nmap-recon/evidence/`](../incidents/INC-005-nmap-recon/) |
| INC-006 | [`incidents/INC-006-scheduled-task-privesc/evidence/`](../incidents/INC-006-scheduled-task-privesc/) |
| INC-007 | [`incidents/INC-007-credential-dumping/evidence/`](../incidents/INC-007-credential-dumping/) |
| INC-008 | [`incidents/INC-008-pass-the-hash/evidence/`](../incidents/INC-008-pass-the-hash/) |
| INC-009 | [`incidents/INC-009-ssh-bruteforce/evidence/`](../incidents/INC-009-ssh-bruteforce/) |
