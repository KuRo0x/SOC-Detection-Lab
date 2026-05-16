# Detection Coverage

This folder tracks which incidents have active detection rules and identifies gaps.

---

## Coverage Matrix

| Incident | Sigma | KQL | EQL | Suricata | Covered |
|---|---|---|---|---|---|
| INC-001 Phishing | — | ✅ | — | — | ✅ |
| INC-002 PowerShell | ✅ | ✅ | — | — | ✅ |
| INC-003 Persistence | ✅ | ✅ | — | — | ✅ |
| INC-004 SMB BF | — | ✅ | — | — | ✅ |
| INC-005 Nmap Recon | — | — | — | ✅ | ✅ |
| INC-006 Sched Task | ✅ | ✅ | — | — | ✅ |
| INC-007 Cred Dump | ✅ (x2) | ✅ | — | — | ✅ |
| INC-008 PTH | ✅ | ✅ | — | — | ✅ |
| INC-009 SSH BF | — | ✅ (x2) | ⏳ pending ECS | — | ⚠️ Partial |

> INC-009 EQL rule blocked pending ECS field parsing. See [`detection-engineering/siem-detections/correlation-rules/`](../../detection-engineering/siem-detections/correlation-rules/).
