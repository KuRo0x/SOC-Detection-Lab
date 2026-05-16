# Log Generators

Synthetic log generation scripts for testing detection rules without running live attacks.

---

## Use Cases

- Test a new Sigma rule before running a real attack
- Replay historical log patterns for rule tuning
- Generate baseline noise to test false positive rates

---

## Planned Scripts

| Script | Generates | Target Index |
|---|---|---|
| `gen-ssh-failures.py` | Fake SSH failed password log lines | `filebeat-*` |
| `gen-sysmon-events.py` | Fake Sysmon Event ID 1 process creation | `winlogbeat-*` |
| `gen-suricata-alerts.py` | Fake Suricata EVE JSON alerts | `suricata-*` |

> Add generator scripts here as they are developed.
