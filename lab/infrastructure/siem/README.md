# SIEM — ELK Stack

> Centralized Security Information and Event Management platform. Collects, parses, and visualizes security telemetry from all lab hosts. Built on the Elastic Stack 8.17.0.

---

## Host

| Field | Value |
|---|---|
| Hostname | soc-brn-ubn |
| OS | Ubuntu 24.04.3 LTS |
| IP | 172.16.0.4/24 |
| RAM | 3.8 GB |
| CPU | 2 vCPU |

---

## Stack Versions

| Component | Version | Process | Port |
|---|---|---|---|
| Elasticsearch | 8.17.0 | java (PID 1526) | 9200 (HTTPS), 9300 (transport) |
| Logstash | 8.17.0 | java (PID 860) | 5044 (Beats input) |
| Kibana | 8.17.0 | node (PID 1166) | 5601 |

All services start automatically on boot (`systemctl enabled`).

---

## Elasticsearch

| Field | Value |
|---|---|
| Cluster name | elasticsearch |
| Node name | soc-brn-ubn |
| Cluster UUID | 8crIfntrRgqpkGWStx7MxA |
| Lucene version | 9.12.0 |
| Build date | 2024-12-11 |
| Security | xpack.security.enabled: true |
| SSL | xpack.security.http.ssl (HTTPS only) |
| Bind address | 0.0.0.0:9200 |

> Elasticsearch requires HTTPS and basic auth. Access via `curl -k https://localhost:9200 -u elastic:<password>`

---

## Logstash

| Field | Value |
|---|---|
| Input | Beats on :5044 |
| Pipeline | Winlogbeat → parse → Elasticsearch |
| Config path | /etc/logstash/conf.d/ |

### Pipeline Flow

```
Winlogbeat (172.16.0.10:5044)
        |
   Logstash :5044
        |
   [filter] parse, enrich, tag
        |
   Elasticsearch (https://localhost:9200)
```

---

## Kibana

| Field | Value |
|---|---|
| URL | http://172.16.0.4:5601 |
| Runtime | Node.js v20.15.1 |
| Index pattern | winlogbeat-* |

---

## Suricata Integration

Suricata runs on the same host and writes alerts to `eve.json`, ingested by Logstash directly:

```
Suricata (ens33 — passive IDS)
        |
   /var/log/suricata/eve.json
        |
   Logstash (file input)
        |
   Elasticsearch
```

---

## Full Data Flow

```
[ Windows Endpoint 172.16.0.10 ]
   Sysmon → Winlogbeat → Logstash :5044
                                    |
[ pfSense 172.16.0.1 ]              ▼
   Firewall logs → Logstash    Elasticsearch
                                    |
[ Suricata (local) ]                ▼
   eve.json → Logstash →      Kibana :5601
```

---

## Lab Role

- **Log aggregation** — single pane for all lab telemetry
- **Alert correlation** — Suricata network alerts + Sysmon endpoint events
- **Detection validation** — confirm detections fire during adversary emulation
- **Threat hunting** — query raw events in Kibana Discover
