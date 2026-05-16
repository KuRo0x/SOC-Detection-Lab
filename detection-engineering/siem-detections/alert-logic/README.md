# Alert Logic

This folder documents the logic for each Elastic Security detection rule — query, index, schedule, severity, risk score, and MITRE mapping.

> Add one `.md` file per rule with full rule configuration details.

---

## Template

```markdown
# Rule: <Rule Name>

| Field | Value |
|---|---|
| Type | Custom Query / EQL / Threshold |
| Index | filebeat-* / winlogbeat-* / suricata-* |
| Query | `<KQL or EQL>` |
| Schedule | Every X minutes |
| Look-back | X minutes |
| Severity | Low / Medium / High / Critical |
| Risk Score | 0–100 |
| MITRE Tactic | TAXXXX — Name |
| MITRE Technique | TXXXX — Name |
| Incident | INC-XXX |
```
