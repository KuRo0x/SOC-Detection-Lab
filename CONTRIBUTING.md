# Contributing

This is a personal blue team portfolio project by **KuRo**. It is not open for external contributions.  
However, the structure and conventions are documented here for reference and reproducibility.

---

## Incident Documentation Standard

Every incident lives under `incidents/INC-XXX-<short-name>/` and must contain:

```
incidents/INC-XXX-<name>/
├── README.md          — summary, environment table, attack overview, detection goals
├── detection.md       — KQL/Sigma queries, rule settings, MITRE mapping
├── investigation.md   — analysis steps, timeline, sample events, Kibana workflow
├── containment.md     — response actions, firewall rules, hardening steps
├── improvements.md    — gaps identified, upgrade path, next engineering phase
├── iocs.md            — network IOCs, host IOCs, hunt queries
├── lessons-learned.md — what worked, what failed, prevention recommendations
└── evidence/          — screenshots, log exports, pcap snippets
```

---

## Naming Conventions

| Type | Format | Example |
|---|---|---|
| Incident folder | `INC-XXX-<kebab-name>` | `INC-009-ssh-bruteforce` |
| Sigma rule file | `INC-XXX_tTTTT_<description>.yml` | `INC-006_t1053_scheduled-task-privesc.yml` |
| Evidence file | `<type>-<description>.<ext>` | `kibana-alerts-screenshot.png` |
| Report file | `<TITLE>_Report.md` | `SSH_A_to_Z_Analysis_Report.md` |

---

## Sigma Rule Standard

All Sigma rules go in `detections/sigma/` and must include:
- `title`, `id` (UUID), `status`, `description`
- `author`, `date`, `modified`
- `logsource` with `product` and `service` or `category`
- `detection` with `selection` and `condition`
- `falsepositives` list
- `level` (low / medium / high / critical)
- `tags` with MITRE ATT&CK technique IDs

---

## MITRE ATT&CK Mapping

Every incident must map to at least one technique using the format:
```
TA00XX — Tactic Name
T1XXX[.00X] — Technique [Sub-technique]
```

---

## Commit Message Format

```
<type>: <short description>

Types:
  docs     — documentation changes
  feat     — new incident or detection
  fix      — correction to existing content
  chore    — cleanup, restructuring
```

Examples:
```
feat: add INC-009 SSH brute force detection
docs: update lab infrastructure with ubuntu-victim IP
fix: correct MITRE technique ID in INC-007
```
