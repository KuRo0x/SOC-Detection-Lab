# Adversary Emulation

This folder contains attack simulation playbooks and scripts used in the KuRo SOC Detection Lab.  
Each subfolder maps to a MITRE ATT&CK tactic.

---

## Structure

| Folder | MITRE Tactic | Related Incidents |
|---|---|---|
| `initial-access/` | TA0001 | INC-001 Phishing |
| `execution/` | TA0002 | INC-002 PowerShell |
| `persistence/` | TA0003 | INC-003 Registry |
| `credential-access/` | TA0006 | INC-004 SMB BF · INC-007 Cred Dump · INC-009 SSH BF |
| `lateral-movement/` | TA0008 | INC-008 Pass-the-Hash |
| `command-and-control/` | TA0011 | Future scenarios |
| `phishing/` | TA0001 | INC-001 Phishing assets |

---

## Usage

All attack simulations are run from **Kali Linux (`172.16.0.11`)** against victim hosts in the isolated VMnet3 network.  
Never run these outside of the lab environment.

---

## Tools Used

| Tool | Purpose |
|---|---|
| `hydra` | SSH / SMB brute-force |
| `nmap` | Network reconnaissance |
| `metasploit` | Exploitation framework |
| `impacket` | Pass-the-Hash / SMB attacks |
| `mimikatz` | Credential dumping |
| PowerShell | Living-off-the-land execution |
