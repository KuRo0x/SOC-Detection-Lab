# Detection Validation

This folder documents the validation of detection rules against real lab data — confirming true positives fire correctly and false positives are understood and controlled.

---

## Subfolders

| Folder | Purpose |
|---|---|
| `true-positive/` | Confirmed rule fires on real attack traffic |
| `false-positive/` | Known benign activity that triggers rules — with tuning notes |

---

## Validation Checklist

For each detection rule, confirm:
- [ ] Rule fires on simulated attack traffic in the lab
- [ ] Rule does NOT fire on normal baseline traffic
- [ ] Alert fields contain useful analyst context (host, user, IP, technique)
- [ ] Severity and risk score are appropriate
- [ ] MITRE tags are correct
- [ ] False positive scenarios are documented
