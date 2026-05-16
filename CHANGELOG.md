# Changelog

All notable changes to the SOC Detection Lab are documented here.  
Format: `[Date] — Change description`

---

## [2026-05-16] — Infrastructure & Documentation
- Added `ubuntu-victim` static IP `172.16.0.20` across all docs
- Rebuilt root `README.md` with full lab layout, VM inventory, incident log, MITRE coverage
- Updated `lab/infrastructure/README.md` with `ubuntu-victim` per-host detail section
- Fixed `architecture/README.md` — removed broken external image reference, updated topology

## [2026-05-13] — INC-009 SSH Brute Force
- Added `ubuntu-victim` (Ubuntu Linux, `172.16.0.20`) as new Linux victim endpoint
- Installed Filebeat 8.19.15 on `ubuntu-victim` — ships `/var/log/auth.log` → `filebeat-*`
- Simulated SSH brute-force attack using Hydra from Kali (`172.16.0.11`)
- Created 2 Elastic Security KQL detection rules: SSH Failed Auth + SSH Successful Login
- Mapped to MITRE ATT&CK T1110 — Brute Force / T1110.001 — Password Guessing
- Documented full incident: README, detection, investigation, containment, IOCs, lessons-learned
- Published `SSH_A_to_Z_Analysis_Report.md` — end-to-end detection engineering report

## [2026-04-XX] — INC-008 Pass-the-Hash
- Simulated Pass-the-Hash attack using Impacket PsExec from Kali
- Created Sigma rule: `INC-008_t1550.002_pass-the-hash-psexec.yml`
- Mapped to MITRE ATT&CK T1550.002 — Pass-the-Hash
- Full incident documentation in `incidents/INC-008-pass-the-hash/`

## [2026-04-XX] — INC-007 Credential Dumping
- Simulated LSASS dump using comsvcs.dll and ProcDump from Windows victim
- Created 2 Sigma rules: comsvcs minidump + procdump LSASS
- Mapped to MITRE ATT&CK T1003 — OS Credential Dumping
- Full incident documentation in `incidents/INC-007-credential-dumping/`

## [2026-04-XX] — INC-006 Scheduled Task PrivEsc
- Simulated privilege escalation via scheduled task creation
- Created Sigma rule: `INC-006_t1053_scheduled-task-privesc.yml`
- Mapped to MITRE ATT&CK T1053 — Scheduled Task/Job
- Full incident documentation in `incidents/INC-006-scheduled-task-privesc/`

## [2026-03-XX] — INC-005 Nmap Reconnaissance
- Simulated network scanning from Kali against lab subnet
- Mapped to MITRE ATT&CK T1046 — Network Service Scanning
- Full incident documentation in `incidents/INC-005-nmap-recon/`

## [2026-03-XX] — INC-004 SMB Brute Force
- Simulated SMB credential brute-force using Hydra
- Mapped to MITRE ATT&CK T1110 — Brute Force
- Full incident documentation in `incidents/INC-004-smb-bruteforce/`

## [2026-03-XX] — INC-003 Persistence via Registry
- Simulated persistence using Windows Registry Run key
- Mapped to MITRE ATT&CK T1547 — Boot/Logon Autostart Execution
- Full incident documentation in `incidents/INC-003-persistence/`

## [2026-03-XX] — INC-002 PowerShell Execution
- Simulated malicious PowerShell execution on Windows victim
- Detected via Sysmon Event ID 1 + Winlogbeat
- Mapped to MITRE ATT&CK T1059.001 — PowerShell
- Full incident documentation in `incidents/INC-002-powershell/`

## [2026-03-14] — INC-001 Phishing Simulation & Lab Init
- Initial lab build: pfSense + Ubuntu SIEM (ELK) + Windows 10 victim + Kali attacker
- Configured VMnet3 isolated network `172.16.0.0/24`
- Installed Elasticsearch, Logstash, Kibana, Suricata on `soc-brn-ubn`
- Installed Sysmon + Winlogbeat on `DESKTOP-DPU3CDQ`
- First incident: phishing simulation and email-based initial access
- Mapped to MITRE ATT&CK T1566 — Phishing
- Full incident documentation in `incidents/INC-001-phishing/`
