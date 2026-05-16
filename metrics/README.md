# Lab Metrics

This folder tracks detection coverage, rule performance, and lab health metrics for the KuRo SOC Detection Lab.

---

## Subfolders

| Folder | Purpose |
|---|---|
| `mitre-coverage/` | ATT&CK technique coverage tracking |
| `detection-coverage/` | Per-incident detection rule coverage |
| `false-positive-rate/` | FP rate tracking per rule over time |

---

## Current Lab Stats (as of May 2026)

| Metric | Value |
|---|---|
| Total incidents documented | 9 |
| Sigma rules written | 4 |
| Elastic KQL rules | 5+ |
| MITRE tactics covered | 6 / 14 |
| MITRE techniques covered | 8 |
| VMs in lab | 5 |
| Log sources | Sysmon · Winlogbeat · Filebeat · Suricata · pfSense |
| Active indices | `winlogbeat-*` · `filebeat-*` · `suricata-*` · `pfsense-*` |
