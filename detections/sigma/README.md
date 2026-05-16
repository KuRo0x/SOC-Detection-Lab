# Sigma Rules

This folder contains all Sigma detection rules written for the KuRo SOC Detection Lab.  
Each rule is tied to a specific incident, MITRE ATT&CK technique, and log source.

---

## Rule Index

| File | Incident | Technique | Log Source | Level |
|---|---|---|---|---|
| `INC-006_t1053_scheduled-task-privesc.yml` | [INC-006](../../incidents/INC-006-scheduled-task-privesc/) | T1053 — Scheduled Task | Windows Security / Sysmon | High |
| `INC-007_t1003_comsvcs-minidump-lsass.yml` | [INC-007](../../incidents/INC-007-credential-dumping/) | T1003 — Credential Dumping | Sysmon EID 1 | Critical |
| `INC-007_t1003_procdump-lsass-dump.yml` | [INC-007](../../incidents/INC-007-credential-dumping/) | T1003 — Credential Dumping | Sysmon EID 1 | Critical |
| `INC-008_t1550.002_pass-the-hash-psexec.yml` | [INC-008](../../incidents/INC-008-pass-the-hash/) | T1550.002 — Pass-the-Hash | Windows Security | High |

---

## Naming Convention

```
INC-XXX_tTTTT[.TTT]_<short-description>.yml
```

- `INC-XXX` — incident reference number
- `tTTTT` — MITRE ATT&CK technique ID (lowercase t)
- `<short-description>` — kebab-case description of what is detected

---

## Rule Standards

All rules in this folder follow the [Sigma specification](https://github.com/SigmaHQ/sigma).  
Required fields per rule:
- `title`, `id` (UUID v4), `status`, `description`
- `author`, `date`
- `logsource` — `product`, `service` or `category`
- `detection` — `selection` + `condition`
- `falsepositives`
- `level`
- `tags` — MITRE ATT&CK technique IDs (`attack.tXXXX`)

---

## Converting Rules to Elastic / KQL

Use [sigma-cli](https://github.com/SigmaHQ/sigma-cli) with the Elasticsearch backend:

```bash
sigma convert -t lucene -p ecs_windows rule.yml
```

Or for Elastic Security EQL:
```bash
sigma convert -t eql -p ecs_windows rule.yml
```
