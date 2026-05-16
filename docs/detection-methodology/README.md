# Detection Methodology

This document describes the detection engineering methodology used in the KuRo SOC Detection Lab — from data source selection to rule deployment.

---

## Detection Engineering Lifecycle

```
1. Understand the attack technique (MITRE ATT&CK)
        ↓
2. Identify the data source that captures it
        ↓
3. Validate raw events exist in Kibana Discover
        ↓
4. Build KQL search to isolate the behavior
        ↓
5. Turn KQL search into an Elastic Security rule
        ↓
6. Convert to Sigma for portability
        ↓
7. Document in incidents/INC-XXX/detection.md
        ↓
8. Identify gaps and plan the next engineering phase
```

---

## Data Sources Used in This Lab

| Source | Agent | Key Event IDs / Fields |
|---|---|---|
| Windows Event Logs | Winlogbeat | EID 4624, 4625, 4688, 4698, 4776 |
| Sysmon | Winlogbeat | EID 1 (process), 3 (network), 7 (DLL), 10 (LSASS), 13 (registry) |
| Linux auth.log | Filebeat | `Failed password`, `Accepted password`, `Invalid user` |
| Suricata IDS | Filebeat/Logstash | `alert.signature`, `src_ip`, `dest_ip`, `proto` |
| pfSense firewall | Logstash UDP 5140 | Firewall block/pass logs |

---

## Detection Tiers

| Tier | Type | Example |
|---|---|---|
| 1 | String matching (KQL) | `message : "Failed password for"` |
| 2 | Field-based filtering | `source.ip : "172.16.0.11" and event.outcome : "failure"` |
| 3 | Threshold / aggregation | Alert after 10 failures from same IP in 5 min |
| 4 | EQL sequence correlation | failure → success from same IP/user within 5 min |

> The lab currently operates at Tier 1-2. Tier 3-4 requires ECS field parsing (see INC-009 gaps).
