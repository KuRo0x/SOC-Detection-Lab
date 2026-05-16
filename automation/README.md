# Automation

This folder contains automation scripts and tools for the KuRo SOC Detection Lab — attack simulation, detection testing, lab deployment, and log generation.

---

## Subfolders

| Folder | Purpose |
|---|---|
| `attack-scripts/` | Automated attack simulation scripts (Hydra, Nmap, Metasploit wrappers) |
| `detection-testing/` | Scripts to validate detection rules fire on known-bad input |
| `lab-deployment/` | Lab setup and configuration scripts |
| `log-generators/` | Scripts to generate synthetic log data for testing |

---

## Usage Warning

> All scripts are designed for use **exclusively within the isolated VMnet3 lab network.**  
> Never run attack scripts outside the lab environment.
