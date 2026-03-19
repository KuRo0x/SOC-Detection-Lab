# Lab Setup Guide

This document explains how to build the SOC Detection Lab from scratch — the same environment used in this project.
It is written for anyone who wants to replicate the lab on their own machine.

---

## 1. Host Requirements

| Component | Requirement |
|-----------|-------------|
| Host OS | Windows 10/11 or Linux |
| RAM | 16 GB minimum (24 GB recommended) |
| CPU | 4+ cores with virtualization enabled (VT-x / AMD-V) |
| Disk | 80–100 GB free |
| Hypervisor | VMware Workstation or VirtualBox |

> Enable virtualization in your BIOS before starting.

---

## 2. Lab Overview

The lab simulates a small enterprise SOC environment with:

- An **attacker** machine generating malicious activity
- A **firewall/IDS** enforcing network policy and detecting threats
- A **victim endpoint** monitored with Sysmon
- A **SIEM** collecting and analyzing all logs

**Traffic path:**
```
Kali Attacker → pfSense Firewall (Suricata IDS) → Windows Victim
                         ↓
                    ELK SIEM (Ubuntu)
```

---

## 3. Virtual Machines

### 3.1 VM 1 — pfSense (Firewall + IDS)

- **ISO:** [pfSense CE](https://www.pfsense.org/download/)
- **RAM:** 1 GB | **Disk:** 10 GB
- **Network Adapters:**
  - Adapter 1: NAT (WAN — internet access)
  - Adapter 2: Host-only / VMnet3 (LAN — lab network)
- **Role:** Gateway, firewall, DNS enforcement, Suricata IDS

**After install:**
1. Set LAN IP to `172.16.0.1/24`
2. Enable Suricata on the LAN interface via `Services > Suricata`
3. Enable Syslog forwarding to the SIEM IP (`172.16.0.4`) under `Status > System Logs > Settings`
4. Block outbound DNS (port 53) to external resolvers in firewall rules

---

### 3.2 VM 2 — Ubuntu Server (SIEM / ELK)

- **ISO:** [Ubuntu Server 22.04 LTS](https://ubuntu.com/download/server)
- **RAM:** 4–6 GB | **Disk:** 40 GB
- **Network:** VMnet3 — IP: `172.16.0.4`
- **Role:** Elasticsearch, Logstash, Kibana, Suricata output collector

**Install ELK Stack:**
```bash
# Add Elastic repo
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update

# Install components
sudo apt install elasticsearch logstash kibana -y

# Enable and start services
sudo systemctl enable --now elasticsearch logstash kibana
```

**Verify services are running:**
```bash
sudo systemctl status elasticsearch
sudo systemctl status logstash
sudo systemctl status kibana
```

Kibana will be accessible at: `http://172.16.0.4:5601`

---

### 3.3 VM 3 — Windows 10 (Victim Endpoint)

- **ISO:** Windows 10 (evaluation or licensed)
- **RAM:** 2–4 GB | **Disk:** 40 GB
- **Network:** VMnet3 — IP: `172.16.0.10`
- **Role:** Monitored endpoint, attack target

**Install Sysmon:**
```powershell
# Download Sysmon from Sysinternals
# https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

# Install with SwiftOnSecurity config (recommended)
sysmon64.exe -accepteula -i sysmonconfig.xml
```

**Install Winlogbeat:**
```powershell
# Download from Elastic
# https://www.elastic.co/downloads/beats/winlogbeat

# Edit winlogbeat.yml:
# output.logstash:
#   hosts: ["172.16.0.4:5044"]

# Install and start service
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

---

### 3.4 VM 4 — Kali Linux (Attacker)

- **ISO:** [Kali Linux](https://www.kali.org/get-kali/)
- **RAM:** 2 GB | **Disk:** 20 GB
- **Network:** VMnet3 — IP: DHCP or `172.16.0.20`
- **Role:** Adversary simulation

No special configuration needed. Used to run attack simulations against the Windows victim.

---

## 4. Network Configuration

| VM | Role | IP Address | Network |
|----|------|------------|---------|
| pfSense | Gateway / Firewall | 172.16.0.1 | VMnet3 |
| Ubuntu SIEM | ELK Stack | 172.16.0.4 | VMnet3 |
| Windows 10 | Victim Endpoint | 172.16.0.10 | VMnet3 |
| Kali Linux | Attacker | 172.16.0.20 | VMnet3 |

All VMs use the same isolated virtual switch (VMnet3). Internet access goes through pfSense only.

---

## 5. Log Ingestion Pipeline

See [`docs/PIPELINE.md`](PIPELINE.md) for the full Logstash pipeline configuration.

**Quick summary of what flows where:**

```
Windows Sysmon → Winlogbeat → Logstash:5044 → Elasticsearch
pfSense Firewall → Syslog → Logstash:514 → Elasticsearch
Suricata Alerts → JSON → Logstash → Elasticsearch
```

---

## 6. Verifying the Lab Works

1. Open Kibana at `http://172.16.0.4:5601`
2. Go to **Discover** and select your index (e.g., `winlogbeat-*`)
3. Run a basic activity on Windows (open cmd, run `whoami`)
4. Search for the event in Kibana — you should see it as a Sysmon Event ID 1

If you see logs appearing in Kibana, your pipeline is working correctly.

---

## 7. Quick Start Checklist

- [ ] Hypervisor installed and virtualization enabled
- [ ] pfSense VM created and LAN configured to 172.16.0.1
- [ ] Suricata enabled on pfSense LAN interface
- [ ] Ubuntu VM created with ELK stack installed and running
- [ ] Logstash configured to receive Beats (port 5044) and Syslog (port 514)
- [ ] Windows VM configured with Sysmon + Winlogbeat pointing to 172.16.0.4
- [ ] Kali VM on same network
- [ ] Test event visible in Kibana

---

## 8. Resources

- [Sysmon Config (SwiftOnSecurity)](https://github.com/SwiftOnSecurity/sysmon-config)
- [Elastic Stack Docs](https://www.elastic.co/guide/index.html)
- [pfSense Docs](https://docs.netgate.com/pfsense/en/latest/)
- [Suricata Docs](https://suricata.readthedocs.io/)
- [MITRE ATT&CK](https://attack.mitre.org/)
