# Log Enrichment

This folder contains enrichment configurations — GeoIP lookups, threat intelligence field additions, and contextual metadata tagging.

---

## Current Enrichments

| Enrichment | Status | Config Location |
|---|---|---|
| GeoIP on `dest_ip` (Suricata) | ✅ Active | `docs/lab-setup/README.md` Logstash config |
| GeoIP on `DestinationIp` (Winlogbeat) | ✅ Active | `docs/lab-setup/README.md` Logstash config |
| Threat Intel lookup | ⏳ Planned | — |
| Asset context tagging | ⏳ Planned | — |

---

## Planned — Threat Intel Enrichment

Enrich alerts with IOC context by querying a local threat intel feed or VirusTotal API:
- Tag known-bad IPs from IOC lists
- Enrich file hashes against VirusTotal
- Add `threat.indicator.type` ECS field
