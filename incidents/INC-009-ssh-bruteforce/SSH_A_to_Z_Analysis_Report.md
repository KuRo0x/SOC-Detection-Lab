# SSH Brute-Force Detection Lab — A to Z Analysis Report
**Lab:** KuRo SOC Detection Lab | **Date:** 2026-05-13 | **Scope:** End-to-end SSH brute-force detection engineering in Elastic SIEM

---

## 1. Executive Summary

This report is a complete A-to-Z analysis of the SSH brute-force detection lab you built in Elastic SIEM. It documents the goal, plan, environment, data sources, investigation process, detection logic, validation steps, response actions, outcomes, gaps, lessons learned, and the next engineering phase.

The work achieved three major outcomes: first, you proved that raw Linux SSH authentication logs can be ingested and queried in Kibana Discover; second, you created practical KQL-based detections for failed and successful SSH authentication; third, you packaged the incident in a professional repository structure that supports review, validation, and portfolio use.

---

## 2. Mission and Plan

The mission of the lab was to simulate an SSH brute-force attack, observe the telemetry, build detections, and document the full incident lifecycle in a way that another analyst or AI reviewer could understand and validate. The plan was intentionally structured like a real SOC / detection engineering workflow rather than a simple demo.

The plan was:
1. Generate SSH brute-force activity against a Linux victim host.
2. Collect the authentication logs with Filebeat.
3. Validate raw events in Kibana Discover.
4. Build KQL searches to isolate failures and successes.
5. Turn the searches into Elastic Security detection rules.
6. Document the incident in a structured repository.
7. Identify gaps and propose the next engineering phase.

---

## 3. Environment Overview

| Component | Value |
|---|---|
| Attacker host | Kali Linux |
| Attacker IP | `172.16.0.11` |
| Victim host | `ubuntu-victim` |
| Victim IP | `172.16.0.x` |
| Attack protocol | SSH (TCP 22) |
| Log source | `/var/log/auth.log` |
| Log shipper | Filebeat 8.19.15 |
| Elastic index | `filebeat-*` |
| ECS status | Raw messages only — no full SSH ECS parsing yet |
| SIEM | Kibana / Elastic Security |

This environment matters because the detection quality depends on both the source logs and the normalization pipeline. In this lab, the logs were visible and searchable, but not fully ECS-mapped, which shaped the rule design.

---

## 4. Attack Simulation

The simulated attack represented a real-world SSH password-guessing workflow. The attacker generated repeated login attempts from `172.16.0.11` to the victim host on port 22, producing repeated `Failed password for` events and at least one `Accepted password for` event.

The raw messages confirmed the behavior clearly. Example failure and success messages observed in the lab:

```
2026-05-12T11:41:26+00:00 ubuntu-victim sshd[7579]: Failed password for jan from 172.16.0.11 port 52294 ssh2
2026-05-12T11:13:18+00:00 ubuntu-victim sshd[1398]: Accepted password for kali from 172.16.0.11 port 45440 ssh2
```

This gave the critical telemetry needed to prove both brute-force activity and successful authentication.

---

## 5. Data Collection

Filebeat 8.19.15 was used to tail `/var/log/auth.log` on the victim host and ship events to Elasticsearch in real time. The raw SSH authentication details arrived inside the `message` field rather than as fully parsed ECS fields such as `source.ip`, `user.name`, or `event.outcome`.

That raw-text condition shaped the rest of the work. It meant reliable searching and alerting using string matches was possible, but clean event correlation with EQL sequence logic was not possible without adding a parsing pipeline first.

---

## 6. Discovery and Validation in Kibana Discover

The first step was to confirm that the log data actually existed in Kibana Discover. Broad and scoped KQL queries were tested to make sure the right messages were present before building rules.

Validation queries used:

```kql
message : "Failed password for"
message : "Accepted password for"
message : "Accepted publickey for"
host.name : "ubuntu-victim" and message : "Failed password for"
host.name : "ubuntu-victim" and message : "172.16.0.11" and message : "Failed password for"
```

A broader hunt query returned approximately **948 events**, which showed the index had rich data but was noisy enough to need scoped rules. That was an important discovery because it proved both the pipeline health and the need for targeted detection logic.

---

## 7. Detection Engineering

Two Elastic Security custom query rules were designed based on the validated KQL logic.

### Rule 1 — Linux SSH Failed Authentication Attempt

```kql
message : ("Failed password for" or "Failed publickey for" or "Invalid user")
```

| Field | Value |
|---|---|
| Severity | Medium |
| Risk score | 47 |
| MITRE Tactic | TA0006 — Credential Access |
| MITRE Technique | T1110 — Brute Force |
| Schedule | Every 1 minute / 1 min look-back |

### Rule 2 — Linux SSH Successful Login

```kql
message : ("Accepted password for" or "Accepted publickey for")
```

| Field | Value |
|---|---|
| Severity | Low |
| Risk score | 21 |
| MITRE Tactic | TA0006 / TA0001 — Credential Access / Initial Access |
| MITRE Technique | T1110 — Brute Force |
| Schedule | Every 1 minute / 1 min look-back |

Both rules were validated in Discover before creation to confirm matching events exist.

---

## 8. EQL Attempt and Limitation

An EQL sequence rule was attempted to correlate failure followed by success from the same source. The query was:

```eql
sequence by host.name, source.ip, user.name with maxspan=5m
  [authentication where event.outcome == "failure"]
  [authentication where event.outcome == "success"]
```

This produced a parse error in the Discover search bar. The root cause was twofold:

1. Kibana Discover only accepts KQL/Lucene — EQL sequence syntax must be run via Dev Tools or the Elastic Security Event Correlation rule type.
2. The ECS fields `source.ip`, `user.name`, `event.outcome`, and `event.category` are not parsed from raw auth log messages yet, so EQL correlation cannot work even if the right interface is used.

This is a realistic data engineering limitation, not an analysis error. It defines the next engineering phase.

---

## 9. Incident Documentation Structure

The full incident was packaged into a structured repository folder that matches the existing lab incident format:

```
incidents/INC-009-ssh-bruteforce/
├── README.md               — incident summary, environment, attack overview, goals
├── detection.md            — validation queries, rule settings, EQL error, upgrade path
├── investigation.md        — analysis flow, sample events, Kibana steps, assessment
├── improvements.md         — rules documented, grok patterns, EQL roadmap, hardening
├── iocs.md                 — network, host, log IOCs and hunt queries
├── containment.md          — block IP, kill sessions, authorized_keys, fail2ban, hardening
├── lessons-learned.md      — what happened, why it worked, detection gaps, prevention
├── SSH_A_to_Z_Analysis_Report.md  — this document
└── evidence/               — placeholder for screenshots
```

---

## 10. Indicators of Compromise

### Network
- Attacker IP: `172.16.0.11`
- Target: `ubuntu-victim` on TCP 22
- High volume of connection attempts from single source

### Host / Log
- `Failed password for` — multiple users (`jan` and others)
- `Accepted password for kali` — confirmed successful login
- `Invalid user` — enumeration of unknown usernames
- sshd PIDs `7579` (failure session) and `1398` (success session)

### Hunt Queries

```kql
message : "172.16.0.11" and message : ("Failed password" or "Accepted password" or "Invalid user")
```

---

## 11. Containment and Response

Containment was documented as a realistic lab response playbook. Key actions:

- Block `172.16.0.11` at pfSense firewall (`ATTACKER_SSH_BLOCK` alias, deny TCP/22)
- Change or disable the `kali` account password
- Kill active SSH sessions from attacker IP
- Audit all `authorized_keys` files for backdoors
- Check cron jobs for persistence
- Harden SSH: `PasswordAuthentication no`, `MaxAuthTries 3`, `PermitRootLogin no`
- Deploy `fail2ban` with a 5-failure, 1-hour ban policy
- Restrict SSH access by IP via `AllowUsers`

---

## 12. Lessons Learned

The biggest lesson is that **raw log visibility is not the same as correlation-ready telemetry**. String-matching KQL rules work well for first-pass detection but stronger analytics require ECS normalization.

Other key takeaways:

| Lesson | Impact |
|--------|--------|
| Password auth was enabled | Direct cause of brute-force success |
| No fail2ban | Attacker could try unlimited passwords |
| Weak/known password on `kali` account | Attack succeeded |
| No ECS field parsing | Blocks EQL, suppression, and field-based correlation |
| No notification connector on rules | Analyst must manually check Alerts UI |
| Repository structure was complete | Makes the incident legible and reviewable |

---

## 13. What Was Achieved

| Objective | Status |
|-----------|--------|
| SSH auth logs ingested via Filebeat | ✅ Confirmed |
| Failure events validated in Discover | ✅ Confirmed |
| Success events validated in Discover | ✅ Confirmed |
| KQL Rule 1 — Failed authentication | ✅ Created |
| KQL Rule 2 — Successful login | ✅ Created |
| MITRE ATT&CK mapping (T1110) | ✅ Applied |
| IOCs documented | ✅ Complete |
| Containment playbook documented | ✅ Complete |
| Lessons learned documented | ✅ Complete |
| EQL attempt made and failure documented | ✅ Documented |
| ECS upgrade path defined | ✅ Documented |
| Full repository incident structure | ✅ Complete |
| Screenshots / evidence artifacts | ⏳ Pending |
| ECS ingest pipeline | ⏳ Next phase |
| EQL Event Correlation rule | ⏳ Blocked on ECS parsing |

---

## 14. Remaining Gaps

1. **No ECS field parsing** — `source.ip`, `user.name`, `event.outcome`, `event.category` are not extracted from raw SSH messages.
2. **No EQL correlation rule** — blocked by gap 1.
3. **No alert suppression by IP** — blocked by gap 1.
4. **No notification connector** — rules alert in Kibana UI only; no email/webhook wired.
5. **No screenshot evidence yet** — `evidence/` folder exists but is empty.

These are the natural next milestones for the lab, not failures.

---

## 15. Next Engineering Phase

The upgrade path in priority order:

1. **Build ECS ingest pipeline** — add a Logstash grok filter or Elasticsearch ingest pipeline to extract:
   - `source.ip`
   - `user.name`
   - `source.port`
   - `event.outcome` (`failure` / `success`)
   - `event.category` (`authentication`)

2. **Upgrade to EQL Event Correlation rule** in Elastic Security:
   ```eql
   sequence by host.name, source.ip, user.name with maxspan=5m
     [authentication where event.outcome == "failure"]
     [authentication where event.outcome == "success"]
   ```

3. **Add alert suppression** by `source.ip` to the failure rule.

4. **Add a Threshold rule** to alert only after N failures from one IP in a rolling window.

5. **Wire notification connector** (email or webhook) to both rules.

6. **Add screenshots** to `evidence/` after the next Hydra run.

---

## 16. AI Reviewer Prompt

If you are an AI reviewing this lab, use the following evaluation criteria:

> Review this SSH brute-force detection lab as a blue-team / SIEM detection engineering project. Evaluate the quality of the incident documentation, the realism of the attack simulation, the correctness of the KQL detections, the appropriateness of the MITRE ATT&CK mapping, the clarity of the investigation and containment steps, and whether the response path is production-oriented or only lab-oriented. Identify strengths, weaknesses, missing evidence, detection gaps, false-positive risks, and the best next technical improvement. Rate the work from 1 to 10 for: (1) realism, (2) detection quality, (3) documentation quality, (4) overall portfolio value.

---

## 17. Final Assessment

This is a strong first-phase detection engineering lab. The structure is professional, the detections are correct for the data available, and the documentation covers the full incident lifecycle. The gap between current capability (KQL string matching) and target capability (EQL field-level correlation) is clearly identified, which is itself a mark of good engineering practice.

The most important next step is ECS parsing. Once that is done, the detection capability will move from basic alerting to true behavioral correlation — a significant improvement that will close the biggest remaining gap in this lab.

---

*Report generated: 2026-05-13 | Lab: KuRo SOC Detection Lab | Author: KuRo*
