# Log Ingestion Pipeline

This document describes the full telemetry pipeline from source systems to Elasticsearch in the SOC Detection Lab.

---

## 1. Pipeline Overview

```
[Windows Endpoint]  →  Winlogbeat  →  Logstash:5044  →  Elasticsearch
[pfSense Firewall]  →  Syslog      →  Logstash:514   →  Elasticsearch
[Suricata IDS]      →  JSON output →  Logstash        →  Elasticsearch
                                                             ↓
                                                          Kibana
```

---

## 2. Logstash Pipeline Configuration

### 2.1 Input: Beats (Winlogbeat)

```ruby
input {
  beats {
    port => 5044
  }
}
```

Receives Windows event logs and Sysmon telemetry from Winlogbeat.

---

### 2.2 Input: Syslog (pfSense)

```ruby
input {
  udp {
    port => 514
    type => "pfsense"
  }
}
```

Receives firewall allow/deny events and DNS enforcement logs from pfSense.

---

### 2.3 Input: Suricata JSON

```ruby
input {
  file {
    path => "/var/log/suricata/eve.json"
    codec => "json"
    type => "suricata"
  }
}
```

Ingests Suricata structured alert events directly from the log file.

---

### 2.4 Filter: Normalize and Enrich

```ruby
filter {
  if [type] == "pfsense" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{GREEDYDATA:fw_message}" }
    }
  }

  if [type] == "suricata" {
    mutate {
      add_field => { "log_source" => "suricata" }
    }
  }

  date {
    match => [ "timestamp", "ISO8601" ]
    target => "@timestamp"
  }
}
```

---

### 2.5 Output: Elasticsearch

```ruby
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "%{type}-%{+YYYY.MM.dd}"
  }
}
```

All events are indexed into daily rolling indices by source type.

---

## 3. Indices in Elasticsearch

| Index Pattern | Source |
|---------------|--------|
| `winlogbeat-*` | Windows + Sysmon events |
| `pfsense-*` | Firewall and DNS logs |
| `suricata-*` | IDS alerts |

---

## 4. Kibana Index Patterns

Configure these index patterns in Kibana under **Stack Management > Index Patterns**:

- `winlogbeat-*`
- `suricata-*`
- `pfsense-*`

Use `@timestamp` as the time field for all patterns.

---

## 5. Verifying Ingestion

```bash
# Check Elasticsearch indices
curl -X GET "localhost:9200/_cat/indices?v"

# Check Logstash is listening
sudo ss -tlnp | grep 5044

# Check Winlogbeat connection from Windows
.\winlogbeat.exe test output
```

If indices appear and event counts grow over time, the pipeline is working correctly.
