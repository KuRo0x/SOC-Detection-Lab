# SIEM Detections — Elastic Security

This folder contains Elastic Security detection rule definitions for the lab — KQL custom query rules, EQL event correlation rules, and threshold rules.

---

## Subfolders

| Folder | Purpose |
|---|---|
| `alert-logic/` | Rule logic documentation — query, threshold, schedule, severity |
| `correlation-rules/` | EQL sequence rules (future — requires ECS field parsing) |

---

## Current Rules in Elastic Security

| Rule Name | Type | Incident | Technique | Severity |
|---|---|---|---|---|
| Linux SSH Failed Authentication Attempt | KQL | INC-009 | T1110.001 | Medium |
| Linux SSH Successful Login | KQL | INC-009 | T1110 | Low |

---

## Next Phase — EQL Correlation

Once ECS field parsing is added via Logstash grok or ingest pipeline, the following EQL rule will be deployed:

```eql
sequence by host.name, source.ip, user.name with maxspan=5m
  [authentication where event.outcome == "failure"]
  [authentication where event.outcome == "success"]
```

This will detect brute-force success patterns (failure → success from same IP/user) as a single correlated alert.
