# Ubuntu Victim — Setup Guide

**Hostname:** `ubuntu-victim`  
**IP:** `172.16.0.20/24`  
**Role:** Linux victim endpoint — SSH brute-force target, Filebeat log shipper  
**Added in:** INC-009 — SSH Brute Force

---

## VM Specs

| Field | Value |
|---|---|
| OS | Ubuntu Linux (Server) |
| IP | `172.16.0.20/24` (static) |
| Gateway | `172.16.0.1` (pfSense) |
| DNS | `172.16.0.1` |
| Network | VMnet3 |
| Services | SSH (TCP 22), Filebeat 8.19.15 |

---

## Step 1 — Set Static IP

Edit `/etc/netplan/00-installer-config.yaml`:

```yaml
network:
  version: 2
  ethernets:
    ens33:
      addresses: [172.16.0.20/24]
      gateway4: 172.16.0.1
      nameservers:
        addresses: [172.16.0.1]
```

```bash
sudo netplan apply
ip a  # confirm 172.16.0.20
```

---

## Step 2 — Enable SSH

```bash
sudo apt update && sudo apt install openssh-server -y
sudo systemctl enable --now ssh
sudo systemctl status ssh
```

Verify from Kali:
```bash
ssh <user>@172.16.0.20
```

---

## Step 3 — Install Filebeat 8.19.15

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update && sudo apt install filebeat -y
filebeat version  # confirm 8.x
```

---

## Step 4 — Configure Filebeat

Edit `/etc/filebeat/filebeat.yml`:

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/auth.log
    fields:
      log_source: filebeat-linux
    fields_under_root: true

output.elasticsearch:
  hosts: ["https://172.16.0.4:9200"]
  username: "elastic"
  password: "<your-elastic-password>"
  ssl.verification_mode: none
  index: "filebeat-%{+yyyy.MM.dd}"

setup.ilm.enabled: false
setup.template.name: "filebeat"
setup.template.pattern: "filebeat-*"
```

```bash
sudo systemctl enable --now filebeat
sudo systemctl status filebeat
```

---

## Step 5 — Verify Logs in Kibana

In Kibana Discover, select `filebeat-*` index and run:

```kql
host.name : "ubuntu-victim"
```

You should see auth.log events appearing within 30 seconds.

---

## Step 6 — Test with SSH Brute Force (INC-009)

From Kali (`172.16.0.11`):

```bash
hydra -l kali -P /usr/share/wordlists/rockyou.txt ssh://172.16.0.20
```

In Kibana, verify:
```kql
host.name : "ubuntu-victim" and message : "Failed password for"
```

> Full incident documentation: [`incidents/INC-009-ssh-bruteforce/`](../../incidents/INC-009-ssh-bruteforce/)
