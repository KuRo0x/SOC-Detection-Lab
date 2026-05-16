# Exports

This folder contains exported Kibana dashboards, saved searches, detection rules, and index patterns for the KuRo SOC Detection Lab.

---

## What to Export

| Asset | How to Export | Format |
|---|---|---|
| Kibana dashboards | Stack Management → Saved Objects → Export | `.ndjson` |
| Elastic Security rules | Security → Rules → Export rules | `.ndjson` |
| Index patterns | Stack Management → Saved Objects → Export | `.ndjson` |
| Kibana visualizations | Stack Management → Saved Objects → Export | `.ndjson` |

---

## How to Import

```
Kibana → Stack Management → Saved Objects → Import → select .ndjson file
```

---

> Add exported `.ndjson` files here to make the lab reproducible.
