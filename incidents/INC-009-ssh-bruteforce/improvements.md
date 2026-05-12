# Improvements – INC-009 SSH Brute Force

## 1. Detection Rules Created in Elastic Security

Two Elastic Security custom query rules were created to detect SSH brute-force activity across all Linux hosts in the lab.

### Rule 1 — Linux SSH Failed Authentication Attempt

- **Rule type:** Custom query
- **Index:** `filebeat-*`
- **Query:** `message : ("Failed password for" or "Failed publickey for" or "Invalid user")`
- **Schedule:** Every 1 minute / 1 minute look-back
- **Severity:** Medium | **Risk score:** 47
- **MITRE:** TA0006 – Credential Access → T1110 – Brute Force
- **Tags:** `linux`, `ssh`, `bruteforce`, `auth`, `lab`

### Rule 2 — Linux SSH Successful Login

- **Rule type:** Custom query
- **Index:** `filebeat-*`
- **Query:** `message : ("Accepted password for" or "Accepted publickey for")`
- **Schedule:** Every 1 minute / 1 minute look-back
- **Severity:** Low | **Risk score:** 21
- **MITRE:** TA0006 – Credential Access / TA0001 – Initial Access → T1110 – Brute Force

Both rules were validated in Kibana Discover before creation, confirming that matching events exist in the `filebeat-*` index.

---

## 2. EQL Upgrade Path (Next Phase)

The current KQL rules alert on individual events but cannot correlate a failure → success sequence. The upgrade path is:

**Phase 1 (done):** KQL custom query rules for failures and successes separately.

**Phase 2 (planned):** Add an Elasticsearch ingest pipeline or Logstash grok filter to parse ECS fields from raw SSH messages:

```
# Grok patterns for Logstash / ingest pipeline
Failed password for %{USER:user.name} from %{IP:source.ip} port %{NUMBER:source.port:int}
Accepted password for %{USER:user.name} from %{IP:source.ip} port %{NUMBER:source.port:int}
Accepted publickey for %{USER:user.name} from %{IP:source.ip} port %{NUMBER:source.port:int}
Invalid user %{USER:user.name} from %{IP:source.ip} port %{NUMBER:source.port:int}
```

Then set on each document:
- `event.category: authentication`
- `event.outcome: failure` (failed events)
- `event.outcome: success` (accepted events)

**Phase 3 (planned):** Once ECS fields exist, create an Event Correlation (EQL) rule in Elastic Security:

```eql
sequence by host.name, source.ip, user.name with maxspan=5m
  [authentication where event.outcome == "failure"]
  [authentication where event.outcome == "success"]
```

This will alert only when a failure is followed by a success from the same source IP and user within 5 minutes — a high-confidence brute-force success indicator.

---

## 3. Alert Suppression and Noise Reduction

- Once ECS fields are parsed, add **alert suppression by `source.ip`** to the failure rule to avoid flooding alerts during a high-rate Hydra run.
- Consider adding a private IP exclusion for internal management IPs to reduce false positives:

```kql
message : ("Failed password for" or "Failed publickey for") and not message : "192.168."
```

---

## 4. Future Hardening Ideas

- Attach a notification action (email, Slack webhook, or Elastic connector) to the **"Linux SSH Failed Authentication Attempt"** rule for real-time analyst alerting.
- Consider deploying `fail2ban` on the victim host alongside Elastic detection to test host-level response combined with SIEM-level alerting.
- Extend Filebeat configuration to collect auth logs from additional Linux VMs in the lab (Metasploitable, DVWA, etc.).
- In future iterations, use a **Threshold rule** type to alert only when a single source IP produces more than N failures in a rolling window, reducing noise while maintaining precision.
- Map the full attack chain in MITRE ATT&CK Navigator:
  - T1595 – Active Scanning (pre-attack reconnaissance)
  - T1110 – Brute Force
  - T1078 – Valid Accounts (post-success)
  - T1021.004 – Remote Services: SSH
