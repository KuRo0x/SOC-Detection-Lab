# Attack Scripts

Real attack simulation scripts used in the KuRo SOC Detection Lab to generate telemetry for detection engineering.
All scripts are run from **Kali Linux (`172.16.0.11`)** against victim hosts inside the isolated **VMnet3 `172.16.0.0/24`** network.

> ⚠️ **WARNING:** Never run these scripts outside the lab environment.

---

## Scripts

| Script | Attack | Attacker | Target | Incident | MITRE |
|---|---|---|---|---|---|
| `ssh-bruteforce.sh` | Hydra SSH password guessing | `172.16.0.11` | ubuntu-victim `172.16.0.20` | [INC-009](../../incidents/INC-009-ssh-bruteforce/) | T1110.001 |
| `smb-bruteforce.sh` | netexec SMB brute-force | `172.16.0.11` | DESKTOP-DPU3CDQ `172.16.0.10` | [INC-004](../../incidents/INC-004-smb-bruteforce/) | T1110 |
| `nmap-recon.sh` | Nmap network discovery | `172.16.0.11` | `172.16.0.0/24` | [INC-005](../../incidents/INC-005-nmap-recon/) | T1046 |
| `pth-psexec.sh` | Impacket Pass-the-Hash | `172.16.0.11` | DESKTOP-DPU3CDQ `172.16.0.10` | [INC-008](../../incidents/INC-008-pass-the-hash/) | T1550.002 |

---

## Expected Log Output per Script

| Script | Log Source | Index | Key Field |
|---|---|---|---|
| `ssh-bruteforce.sh` | `/var/log/auth.log` via Filebeat | `filebeat-*` | `message: "Failed password"` |
| `smb-bruteforce.sh` | Windows Security Log via Winlogbeat | `winlogbeat-*` | `event.code: "4625"` |
| `nmap-recon.sh` | Suricata EVE JSON via pfSense | `suricata-*` | `event.module: "suricata"` |
| `pth-psexec.sh` | Windows Security Log via Winlogbeat | `winlogbeat-*` | `event.code: "4624" LogonType: 3` |

---

## Usage

```bash
# From Kali (172.16.0.11)
chmod +x ssh-bruteforce.sh
./ssh-bruteforce.sh
```

Each script prints the expected Kibana KQL query at the end so you can verify detection immediately after running.
