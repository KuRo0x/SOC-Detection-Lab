# Lab Deployment

Scripts and configuration files to automate lab setup and VM configuration.

---

## Manual Setup Guide

For full step-by-step manual setup instructions, see:  
[`docs/lab-setup/README.md`](../../docs/lab-setup/README.md)

---

## Planned Automation

| Script | Purpose |
|---|---|
| `install-elk.sh` | Install and configure Elasticsearch + Logstash + Kibana on Ubuntu SIEM |
| `install-filebeat.sh` | Install and configure Filebeat on ubuntu-victim |
| `install-sysmon.ps1` | Install Sysmon + config on Windows victim |
| `install-winlogbeat.ps1` | Install and configure Winlogbeat on Windows victim |
| `configure-pfsense.sh` | pfSense CLI configuration helpers |

> Add scripts here as they are developed.
