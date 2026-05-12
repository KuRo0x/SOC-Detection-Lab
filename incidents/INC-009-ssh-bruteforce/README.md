# INC-009 – SSH Brute Force Detection (Linux Auth Log)

## Summary

This incident simulates an external attacker performing a brute-force attack against SSH on a Linux host using `hydra` (or manual SSH). The attack generates a high volume of failed password attempts in `/var/log/auth.log` and ultimately results in a successful authentication, confirming that credential access was achieved.

The goal of this case is to validate that the lab can (1) capture failed and successful SSH authentication events from Linux auth logs via Filebeat, (2) surface them in Elastic Kibana Discover, and (3) detect the attack using Elastic Security detection rules mapped to MITRE ATT&CK.

---

## Environment

| Component | Value |
|-----------|-------|
| Attacker | Kali Linux running `hydra` / manual SSH (`172.16.0.11`) |
| Victim | Ubuntu Linux (`ubuntu-victim`, `172.16.0.x`) |
| Log source | `/var/log/auth.log` |
| Log shipper | Filebeat 8.19.15 → Elasticsearch |
| Index pattern | `filebeat-*` |
| ECS version | 8.0.0 |
| Detection | Elastic Security custom query rule |

---

## Attack Overview

1. The attacker uses `hydra` with a wordlist against SSH on the victim host:
   - Multiple failed password attempts appear as: `Failed password for <user> from 172.16.0.11 port <port> ssh2`
   - A successful login appears as: `Accepted password for <user> from 172.16.0.11 port <port> ssh2`
2. Filebeat tails `/var/log/auth.log` and forwards all sshd events to Elasticsearch in real time.
3. The Elastic Security rule **"Linux SSH Failed Authentication Attempt"** runs every minute over `filebeat-*` and generates alerts on matching failure events.
4. A companion rule **"Linux SSH Successful Login"** alerts on any successful SSH login for cross-correlation.
5. Kibana Discover and the Alerts view confirm both the raw events and the triggered alerts during the brute-force window.

---

## Key Evidence

- **Kibana Discover screenshot** showing a time-based spike of `Failed password for` messages in the last 15 minutes.
- **Kibana Alerts screenshot** showing alerts from the rule **"Linux SSH Failed Authentication Attempt"** with `host.name: ubuntu-victim` and source referencing `172.16.0.11`.
- **Attacker terminal screenshot** showing repeated SSH failures followed by one successful login.

> Place screenshots under `incidents/INC-009-ssh-bruteforce/evidence/` and reference them from `investigation.md`.

---

## Detection Goals

- Identify bursts of failed SSH password or publickey attempts from a single source in a short time window.
- Detect a successful SSH login that follows a series of failures (brute-force success pattern).
- Generate Elastic Security alerts mapped to MITRE ATT&CK:
  - Technique: **T1110 – Brute Force**
  - Sub-technique: **T1110.001 – Password Guessing**
  - Tactic: **TA0006 – Credential Access**
- Provide a foundation for upgrading to EQL event correlation (failure → success sequence) once ECS field parsing is in place.

---

## Gap Analysis (High-Level)

- Filebeat ingests raw auth log lines — `source.ip`, `user.name`, and `event.outcome` are **not yet parsed into ECS fields**. All detection relies on `message` string matching.
- Detection rules are currently keyword-based (KQL); they generate one alert per matching log line rather than correlating sequences.
- No automated notification action is attached to the rules yet — analysts must monitor the Kibana Alerts UI.
- EQL sequence correlation (failure → success on same IP and user) is the next phase and requires an ingest pipeline or Logstash grok to parse ECS fields first.

These gaps are expanded in `detection.md`, `investigation.md`, and `improvements.md`.

---

## Next Steps

- Create both KQL detection rules in Elastic Security and verify they fire on live Hydra traffic.
- Add an Elasticsearch ingest pipeline or Logstash grok filter to parse `source.ip`, `user.name`, `event.outcome`, and `event.category` from raw SSH messages.
- Once ECS fields are populated, upgrade to an EQL Event Correlation rule for failure → success sequence detection.
- Add a notification action (email or webhook) to both rules for real-time analyst alerting.
- Extend coverage to additional Linux hosts as they are added to the lab.
