# SSH Brute-Force Detection Lab — Full Report
**Lab:** KuRo SOC Detection Lab | **Date:** 2026-05-12 | **Stack:** ELK (Elasticsearch, Logstash, Kibana) + Filebeat

---

## Executive Summary

This report documents the complete detection engineering workflow for SSH brute-force attacks built in Elastic SIEM using Filebeat-ingested Linux auth logs. The lab covers source data validation, KQL query development, Discover testing, detection rule creation, and the planned upgrade path to EQL event correlation.

---

## Lab Environment

| Component | Value |
|-----------|-------|
| Victim machine | `ubuntu-victim` |
| Attacker IP | `172.16.0.11` |
| Log source | `/var/log/auth.log` |
| Log shipper | Filebeat 8.19.15 |
| Elasticsearch index | `filebeat-2026.05.12` (pattern: `filebeat-*`) |
| ECS version | 8.0.0 |
| Kibana | 8.x (Discover + Security) |

---

## Source Data

Raw SSH auth events are ingested as plain text in the `message` field (and duplicated in `event.original`). The data is **not ECS-normalized** for SSH — there are no structured `source.ip`, `user.name`, or `event.outcome` fields parsed from the log line. All usable information is embedded in the raw `message` string.

**Sample failure event:**
```
2026-05-12T11:41:26.426239+00:00 ubuntu-victim sshd[7579]: Failed password for jan from 172.16.0.11 port 52294 ssh2
```

**Sample success event:**
```
2026-05-12T11:13:18.104652+00:00 ubuntu-victim sshd[1398]: Accepted password for kali from 172.16.0.11 port 45440 ssh2
```

**Key raw-log patterns to match:**

| Event type | Pattern in `message` |
|------------|----------------------|
| Password failure | `Failed password for` |
| Publickey failure | `Failed publickey for` |
| Invalid user | `Invalid user` |
| Password success | `Accepted password for` |
| Publickey success | `Accepted publickey for` |

---

## Phase 1 — Discover Validation (KQL)

Before building any detection rule, all queries were tested in **Kibana Discover** using KQL (Kibana Query Language) to confirm that matching events exist in the index.

### Baseline search (broad, all systems)
```kql
message : ("Failed password for" or "Accepted password for" or "Accepted publickey for")
```
**Result:** ~948 events — valid but noisy, mixing success and failure in one query.

### Recommended validation queries (split by intent)

**Step 1 — Confirm failures exist:**
```kql
message : "Failed password for"
```

**Step 2 — Confirm successes exist:**
```kql
message : "Accepted password for"
```

**Step 3 — Confirm key-based logins:**
```kql
message : "Accepted publickey for"
```

**Step 4 — Scope to specific host:**
```kql
host.name : "ubuntu-victim" and message : "Failed password for"
```

**Step 5 — Scope to specific attacker IP:**
```kql
host.name : "ubuntu-victim" and message : "172.16.0.11" and message : "Failed password for"
```

---

## Phase 2 — Detection Rule (Elastic Security)

### Why NOT EQL Sequence in Discover
EQL `sequence by ...` syntax is a standalone query language that runs via the `_eql/search` API or in Elastic Security's **Event Correlation** rule type. It **cannot** be pasted into the Discover search bar, which only accepts KQL/Lucene expressions. This caused the parse errors seen during testing.

### Rule 1 — SSH Failed Password (All Systems)

**Rule type:** Custom query  
**Index pattern:** `filebeat-*`

**Query:**
```kql
message : ("Failed password for" or "Failed publickey for" or "Invalid user")
```

**Settings:**

| Field | Value |
|-------|-------|
| Name | `Linux SSH Failed Authentication Attempt` |
| Description | Detects failed SSH password or key-based authentication attempts in Linux auth logs ingested via Filebeat. |
| Severity | Medium |
| Risk score | 47 |
| MITRE ATT&CK Tactic | Credential Access |
| MITRE ATT&CK Technique | T1110 — Brute Force |
| Schedule | Every 1 minute |
| Look-back | 1 minute |
| Tags | `linux`, `ssh`, `bruteforce`, `auth`, `lab` |

---

### Rule 2 — SSH Successful Login (All Systems)

**Rule type:** Custom query  
**Index pattern:** `filebeat-*`

**Query:**
```kql
message : ("Accepted password for" or "Accepted publickey for")
```

**Settings:**

| Field | Value |
|-------|-------|
| Name | `Linux SSH Successful Login` |
| Description | Detects successful SSH password or key-based authentication in Linux auth logs. Used as a companion to the failed login rule for brute-force correlation. |
| Severity | Low |
| Risk score | 21 |
| MITRE ATT&CK Tactic | Credential Access / Initial Access |
| MITRE ATT&CK Technique | T1110 — Brute Force (success after attempts) |
| Schedule | Every 1 minute |
| Look-back | 1 minute |

---

## Phase 3 — Upgrade Path (EQL Correlation)

Once both KQL rules are confirmed firing correctly, the next step is a proper **Event Correlation** rule in Elastic Security using EQL.

### How to run EQL (correct methods)

**Method A — Dev Tools (testing only):**
```json
GET filebeat-*/_eql/search
{
  "query": """
  sequence by host.name, source.ip, user.name with maxspan=5m
    [authentication where event.outcome == "failure"]
    [authentication where event.outcome == "success"]
  """
}
```

**Method B — Security → Rules → Create new rule → Event Correlation (EQL):**
```eql
sequence by host.name, source.ip, user.name with maxspan=5m
  [authentication where event.outcome == "failure"]
  [authentication where event.outcome == "success"]
```

### Important caveat
The current Filebeat data is **not ECS-mapped** for SSH events — `event.category`, `event.outcome`, `source.ip`, and `user.name` are not parsed. The EQL sequence rule above requires a Logstash/ingest pipeline that extracts those fields from the raw `message` string before it will work.

**To enable the EQL rule, add a Logstash grok pattern or Elasticsearch ingest pipeline:**
```
SSHD_FAIL Failed password for %{USER:user.name} from %{IP:source.ip} port %{NUMBER:source.port}
SSHD_ACCEPT Accepted password for %{USER:user.name} from %{IP:source.ip} port %{NUMBER:source.port}
```

Then add `event.outcome: failure` or `event.outcome: success` to the parsed documents, and `event.category: authentication`.

---

## Current State vs. Target State

| Capability | Current state | Target state |
|------------|--------------|--------------|
| Failure events visible in Discover | ✅ Yes | ✅ Done |
| Success events visible in Discover | ✅ Yes | ✅ Done |
| Custom query KQL rule (failure) | ✅ Ready to create | ✅ Done |
| Custom query KQL rule (success) | ✅ Ready to create | ✅ Done |
| ECS field parsing (`source.ip`, `user.name`, `event.outcome`) | ❌ Not yet | 🔲 Next phase |
| EQL Sequence rule (failure → success correlation) | ❌ Blocked (no ECS fields) | 🔲 After ECS parsing |
| Alert suppression by `source.ip` | ❌ Not yet | 🔲 After ECS fields |

---

## Recommended Next Steps

1. **Create Rule 1** — SSH Failed Authentication (KQL) in Elastic Security now.
2. **Create Rule 2** — SSH Successful Login (KQL) in Elastic Security now.
3. **Test both rules** by running Hydra or manual SSH against the victim and verifying alerts appear.
4. **Add ECS parsing** — configure a Logstash grok or Elasticsearch ingest pipeline to extract `source.ip`, `user.name`, `event.outcome`, and `event.category` from raw `message`.
5. **Upgrade to EQL** — once ECS fields are populated, build the Event Correlation rule in Security for the failure → success sequence.

---

## Context for External AI Prompt

> **Lab context:** Filebeat Linux auth logs in `filebeat-*`. SSH events are raw text in `message`, example: `Failed password for jan from 172.16.0.11 port 52294 ssh2` and `Accepted password for kali from 172.16.0.11 port 45440 ssh2`. No ECS field parsing exists yet — `source.ip`, `user.name`, `event.outcome`, `event.category` are not mapped. Working KQL filter: `message : ("Failed password for" or "Failed publickey for" or "Invalid user")`. Goal: improve this rule to be more professional and production-grade. Options include: (1) add an ingest pipeline to parse ECS fields, then use EQL sequence correlation; (2) use a Threshold rule to alert after N failures within a window; (3) improve noise reduction with private IP exclusions or whitelist logic. Reference Elastic's official SSH brute-force detection rules for best practices.

---

*Report generated: 2026-05-12 | Lab: KuRo SOC Detection Lab*
