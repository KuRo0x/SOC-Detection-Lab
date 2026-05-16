# Telemetry Pipeline

This folder documents the full log collection and enrichment pipeline for the KuRo SOC Detection Lab.

---

## Pipeline Overview

```
[ Windows Victim ]         [ Linux Victim ]        [ pfSense / Suricata ]
  Sysmon + Winlogbeat        Filebeat 8.19.15         EVE JSON + Syslog
        |                         |                          |
        └──────────── TCP 5044 ───┴────── UDP 5140 ──────────┘
                                  |
                          [ Logstash 8.x ]
                      parse · enrich · route
                                  |
                     [ Elasticsearch 8.x ]
                    winlogbeat-* / filebeat-* /
                    suricata-* / pfsense-*
                                  |
                           [ Kibana 8.x ]
                     Discover · Alerts · Dashboards
```

---

## Subfolders

| Folder | Purpose |
|---|---|
| `log-ingestion/` | Filebeat and Winlogbeat configuration files |
| `normalization/` | Logstash pipelines and ECS mapping configs |
| `enrichment/` | GeoIP, threat intel lookups, field enrichment |

---

## Index Patterns

| Index | Source | Agent |
|---|---|---|
| `winlogbeat-*` | Windows Event Logs + Sysmon | Winlogbeat |
| `filebeat-*` | Linux auth.log + other system logs | Filebeat |
| `suricata-*` | Suricata EVE JSON alerts | Filebeat / Logstash |
| `pfsense-*` | pfSense firewall syslog | Logstash UDP 5140 |
