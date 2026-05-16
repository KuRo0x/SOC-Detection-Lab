# Attack Scripts

Automated attack simulation scripts used to generate telemetry for detection engineering in the lab.

---

## Planned Scripts

| Script | Attack | Target | Related Incident |
|---|---|---|---|
| `ssh-bruteforce.sh` | Hydra SSH password guessing | ubuntu-victim `172.16.0.20` | INC-009 |
| `smb-bruteforce.sh` | Hydra SMB credential brute-force | DESKTOP `172.16.0.10` | INC-004 |
| `nmap-recon.sh` | Nmap network scan of VMnet3 | `172.16.0.0/24` | INC-005 |
| `pth-psexec.sh` | Impacket Pass-the-Hash | DESKTOP `172.16.0.10` | INC-008 |

> Add scripts here as they are developed. Each script must include a header comment describing the attack, target, expected log output, and which detection rule it validates.
