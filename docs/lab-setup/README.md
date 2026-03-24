# Lab Setup Guide

This guide walks you through building the exact SOC Detection Lab used in this project from scratch.  
Follow it in order and you will end up with a fully working lab: attacker, firewall, victim endpoint, and SIEM — all talking to each other.

---

## What You Are Building

```
┌─────────────────────────────────────────────────────┐
│                  Host Machine                        │
│                                                      │
│  ┌──────────┐    ┌──────────────┐    ┌───────────┐  │
│  │  Kali    │───▶│   pfSense    │───▶│ Windows 10│  │
│  │ Attacker │    │ FW + Suricata│    │  + Sysmon │  │
│  └──────────┘    └──────┬───────┘    └─────┬─────┘  │
│                         │                  │        │
│                         ▼                  ▼        │
│                  ┌──────────────────────────────┐   │
│                  │     Ubuntu SIEM (ELK Stack)   │   │
│                  │  Elasticsearch + Logstash      │   │
│                  │  Kibana + Suricata output      │   │
│                  └──────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
                     Network: VMnet3 (172.16.0.0/24)
```

---

## Host Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Windows 10/11 or Linux | Windows 11 |
| RAM | 16 GB | 24 GB |
| CPU | 4 cores + VT-x/AMD-V enabled | 6+ cores |
| Disk | 80 GB free | 120 GB free |
| Hypervisor | VMware Workstation or VirtualBox | VMware Workstation |

> Make sure **virtualization is enabled in BIOS** before you start.

---

## Network Plan

All VMs live on an isolated virtual switch (**VMnet3**). Internet goes out through pfSense only.

| VM | Role | IP Address |
|----|------|------------|
| pfSense | Firewall + IDS gateway | `172.16.0.1` |
| Ubuntu Server | SIEM (ELK Stack) | `172.16.0.4` |
| Windows 10 | Victim endpoint | `172.16.0.10` |
| Kali Linux | Attacker | `172.16.0.11` *(DHCP from pfSense)* |

---

## Step 1 — Create the Virtual Network

**VMware Workstation:**
1. Open `Edit > Virtual Network Editor`
2. Add a new network → select **VMnet3**
3. Set type to **Host-only**
4. Subnet IP: `172.16.0.0`, Mask: `255.255.255.0`
5. Enable DHCP so Kali gets an IP automatically

**VirtualBox:**
1. Go to `File > Host Network Manager`
2. Create a new host-only adapter
3. Set IP to `172.16.0.1`, mask `255.255.255.0`
4. Enable DHCP server

---

## Step 2 — pfSense (Firewall + IDS)

### Install
- Download: [pfSense CE ISO](https://www.pfsense.org/download/)
- RAM: `1 GB` | Disk: `10 GB`
- **Adapter 1:** NAT (WAN — internet)
- **Adapter 2:** VMnet3 (LAN — lab network)

Boot the ISO and follow the install wizard. Accept defaults.

### Configure LAN Interface
After boot, set LAN IP:
```
Option 2 → Set interface(s) IP address
LAN → 172.16.0.1 / 24
Enable DHCP: yes (range 172.16.0.10 – 172.16.0.50)
```

### Enable Suricata on LAN
1. Go to `System > Package Manager` → install **Suricata**
2. Go to `Services > Suricata > Interfaces` → Add LAN
3. Enable **EVE JSON log output**
4. Enable rule categories: `ET Open` (Emerging Threats)
5. Start the interface

### Enable Syslog Forwarding to SIEM
1. Go to `Status > System Logs > Settings`
2. Enable remote syslog
3. Remote server: `172.16.0.4:5140`, protocol `UDP`

> **Note:** We use port `5140` instead of the standard `514` because Linux blocks ports below 1024 for non-root processes. Logstash runs as a non-root user so it cannot bind to port 514.

---

## Step 3 — Ubuntu Server (SIEM)

### Install
- Download: [Ubuntu Server 22.04 LTS](https://ubuntu.com/download/server)
- RAM: `4–6 GB` | Disk: `40 GB`
- Network: VMnet3 → static IP `172.16.0.4`

Set static IP during install or after via `/etc/netplan/`:
```yaml
network:
  version: 2
  ethernets:
    ens33:
      addresses: [172.16.0.4/24]
      gateway4: 172.16.0.1
      nameservers:
        addresses: [172.16.0.1]
```
```bash
sudo netplan apply
```

### Install Elasticsearch
```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update && sudo apt install elasticsearch -y
```

Edit `/etc/elasticsearch/elasticsearch.yml`:
```yaml
network.host: 0.0.0.0
http.port: 9200
xpack.security.enabled: true
```
```bash
sudo systemctl enable --now elasticsearch
# Verify:
curl -sk -u elastic:yourpassword https://localhost:9200
```

### Install Logstash
```bash
sudo apt install logstash -y
```

Create pipeline config at `/etc/logstash/conf.d/master-lab.conf`:
```ruby
input {
  file {
    path => "/var/log/suricata/eve.json"
    codec => "json"
    start_position => "beginning"
    add_field => { "log_source" => "suricata" }
  }
  beats {
    port => 5044
    add_field => { "log_source" => "winlogbeat" }
  }
  udp {
    port => 5140
    type => "syslog"
    add_field => { "log_source" => "pfsense" }
  }
}

filter {
  if [dest_ip] and [event_type] {
    if [dest_ip] !~ /^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\./ {
      geoip {
        source => "dest_ip"
        target => "geo"
      }
    }
  }

  if [winlog][event_data][DestinationIp] {
    if [winlog][event_data][DestinationIp] !~ /^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\./ {
      geoip {
        source => "[winlog][event_data][DestinationIp]"
        target => "geo"
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["https://localhost:9200"]
    user => "elastic"
    password => "${ES_PWD}"
    ssl_verification_mode => "none"
    index => "%{log_source}-%{+YYYY.MM.dd}"
  }
}
```

Set the Elasticsearch password as an environment variable:
```bash
sudo nano /etc/environment
# Add this line:
ES_PWD=yourpassword
```
```bash
sudo systemctl enable --now logstash
sudo ss -tlnup | grep 5044
```

### Install Kibana
```bash
sudo apt install kibana -y
```

Edit `/etc/kibana/kibana.yml`:
```yaml
server.host: "0.0.0.0"
server.port: 5601
elasticsearch.hosts: ["https://localhost:9200"]
```
```bash
sudo systemctl enable --now kibana
```

Access Kibana at: **http://172.16.0.4:5601**

### Install Suricata
```bash
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update && sudo apt install suricata -y
```

Edit `/etc/suricata/suricata.yaml` — set the interface and EVE log:
```yaml
af-packet:
  - interface: ens33

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - dns
        - http
        - tls
```
```bash
sudo systemctl enable --now suricata
```

---

## Step 4 — Windows 10 (Victim Endpoint)

### Install
- RAM: `2–4 GB` | Disk: `40 GB`
- Network: VMnet3 → static IP `172.16.0.10`
- Gateway: `172.16.0.1` | DNS: `172.16.0.1`

### Install Sysmon
1. Download [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Download [SwiftOnSecurity Sysmon config](https://github.com/SwiftOnSecurity/sysmon-config) (`sysmonconfig-export.xml`)
3. Open PowerShell as Admin:
```powershell
.\sysmon64.exe -accepteula -i sysmonconfig-export.xml
```
4. Verify it is running:
```powershell
Get-Service sysmon64
```

**Key Event IDs you will see in Kibana:**
| Event ID | What it captures |
|----------|------------------|
| 1 | Process creation (with full command line) |
| 3 | Network connection |
| 7 | Image/DLL loaded |
| 11 | File created |
| 13 | Registry value set |
| 22 | DNS query |

### Install Winlogbeat
1. Download [Winlogbeat](https://www.elastic.co/downloads/beats/winlogbeat)
2. Extract to `C:\Program Files\Winlogbeat`
3. Edit `winlogbeat.yml`:
```yaml
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Security
  - name: System

output.logstash:
  hosts: ["172.16.0.4:5044"]

logging.level: info
```
4. Install and start:
```powershell
cd "C:\Program Files\Winlogbeat"
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```
5. Test the connection:
```powershell
.\winlogbeat.exe test output
```

---

## Step 5 — Kali Linux (Attacker)

- Download: [Kali Linux](https://www.kali.org/get-kali/)
- RAM: `2 GB` | Disk: `20 GB`
- Network: VMnet3 → gets IP via DHCP from pfSense (currently `172.16.0.11`)

No special config needed. This is your attack machine.

---

## Step 6 — Kibana Index Patterns

Once logs start flowing, set up index patterns in Kibana:
1. Go to `Stack Management > Index Patterns > Create index pattern`
2. Create these three:
   - `winlogbeat-*` (Windows + Sysmon events)
   - `suricata-*` (IDS alerts)
   - `pfsense-*` (firewall logs)
3. Set **@timestamp** as the time field for all three

---

## Step 7 — Verify Everything Works

```bash
# On Ubuntu — check all services are running
sudo systemctl status elasticsearch logstash kibana suricata

# Check Elasticsearch has indices
curl -sk -u elastic:$ES_PWD https://localhost:9200/_cat/indices?v

# Check Logstash is listening
sudo ss -tlnup | grep 5044

# Check pfSense syslog is arriving
sudo tcpdump -i ens33 udp port 5140 -c 5
```

On Windows — open `cmd` and run:
```cmd
whoami
ipconfig
```

Then go to Kibana → Discover → select `winlogbeat-*` → you should see **Sysmon Event ID 1** for the `whoami` execution appear within seconds.

**If you see that event in Kibana — your lab is fully working. ✓**

---

## Troubleshooting

| Problem | Check |
|---------|-------|
| No logs in Kibana | `winlogbeat.exe test output` on Windows |
| Logstash not receiving Beats | `sudo ss -tlnup \| grep 5044` on Ubuntu |
| Logstash not receiving syslog | `sudo tcpdump -i ens33 udp port 5140 -c 5` |
| Elasticsearch down | `curl -sk -u elastic:$ES_PWD https://localhost:9200` |
| Suricata not alerting | `sudo tail -f /var/log/suricata/eve.json` |
| pfSense syslog not arriving | Confirm pfSense remote log server is set to `172.16.0.4:5140` |
| Permission denied on UDP port | Use port 5140 or higher — Linux blocks ports below 1024 for non-root |

---

## What's Next

Once your lab is up:
- Run attacks from Kali and investigate them in Kibana
- See [`docs/detection-methodology/`](../detection-methodology/) for detection rules
- See [`docs/investigation-methodology/`](../investigation-methodology/) for the analyst workflow
- See [`incidents/`](../../incidents/) for documented case studies from this lab
