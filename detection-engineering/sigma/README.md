# Sigma Rules

Detection rules written in standard Sigma format, organized by MITRE ATT&CK tactic.
All rules are portable to any Sigma-compatible SIEM backend.

---

## Structure

```
sigma/
├── execution/        ← Execution-based detections
├── persistence/      ← Persistence-based detections
└── high-fidelity/    ← Validated, low false-positive rules
```

---

## Rule Index

### execution/

| Rule | MITRE | Level |
|---|---|---|
| `powershell_encoded_command_medium.yml` | T1059.001 | Medium |
| `office_powershell_download.yml` | T1059.001, T1204.002 | High |

### persistence/

| Rule | MITRE | Level |
|---|---|---|
| `sc_service_create_medium.yml` | T1543.003 | Medium |
| `schtasks_create_medium.yml` | T1053.005 | Medium |

### high-fidelity/

| Rule | MITRE | Level |
|---|---|---|
| `powershell_encoded_command.yml` | T1059.001 | High |
| `sc_service_create_suspicious_high.yml` | T1543.003 | High |
| `schtasks_create_suspicious_high.yml` | T1053.005 | High |
| `script_host_to_powershell_stealth_high.yml` | T1059.001 | High |

---

## Notes

- All rules are `status: experimental`
- Rules are authored by KuRo and validated against live lab telemetry
- False positive filters are included where applicable
