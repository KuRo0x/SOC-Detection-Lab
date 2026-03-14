# Log Ingestion & Processing Pipeline

This document describes how telemetry enters the SIEM, how it is processed, enriched, and indexed.

---

## 1. Pipeline Design

All telemetry flows through **Logstash** — no source writes directly to Elasticsearch.

Logstash acts as:
- Validation layer
- Normalization layer  
- Enrichment layer

This mirrors real-world SOC and MSSP architectures.

---

## 2. Ingestion Sources

| Source | Agent | Transport | Port |
|---|---|---|---|
| Windows 10 | Winlogbeat | TCP (Beats) | 5044 |
| pfSense | — | Syslog | — |
| Suricata | — | JSON file input | — |

---

## 3. Logstash Pipeline Stages

### Input
- Beats input (TCP 5044) — Windows telemetry
- Syslog input — pfSense logs
- File input — Suricata JSON alerts

### Parsing & Normalization
- Logs parsed into structured fields
- Normalized into consistent event formats
- Tagged by source and log type

### Enrichment
- GeoIP enrichment for public IPs only
- Internal (RFC1918) addresses excluded
- Applied after parsing to avoid schema conflicts

### Output / Routing
- Source-specific indices with daily rotation:
  - `winlogbeat-*`
  - `pfsense-*`
  - `suricata-*`

---

## 4. Security Decisions

- No direct endpoint-to-Elasticsearch access
- All data must pass through Logstash validation
- No credentials hardcoded in configs or documentation

---

## 5. Scope Notes

- Pipeline is for defensive monitoring only
- No inline blocking performed
- Design prioritizes visibility, integrity, and explainability
