# Log Ingestion

This folder contains Filebeat and Winlogbeat configuration files used in the lab.

---

## Filebeat — ubuntu-victim (`172.16.0.20`)

```yaml
# /etc/filebeat/filebeat.yml
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
  password: "<password>"
  ssl.verification_mode: none
  index: "filebeat-%{+yyyy.MM.dd}"
```

---

## Winlogbeat — DESKTOP-DPU3CDQ (`172.16.0.10`)

```yaml
# C:\Program Files\Winlogbeat\winlogbeat.yml
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Security
  - name: System

output.logstash:
  hosts: ["172.16.0.4:5044"]
```

---

> Full setup instructions: [`docs/lab-setup/README.md`](../../../docs/lab-setup/README.md)
