# Investigation – INC-009 SSH Brute Force

## 1. Initial Observation

- A brute-force / password-guessing attack was launched from the Kali attacker VM (`172.16.0.11`) against the Ubuntu victim host (`ubuntu-victim`) over SSH (TCP 22).
- The attacker used `hydra` (or manual SSH attempts) with a wordlist targeting local user accounts.
- Auth log entries on the victim showed repeated `Failed password for` messages followed by an `Accepted password for` message, confirming that a valid credential was found and used.

---

## 2. Log Source Identification

- The Ubuntu victim is configured with Filebeat 8.19.15 to tail `/var/log/auth.log` and forward events to Elasticsearch.
- **No ECS parsing pipeline exists** — SSH events arrive as raw log lines in the `message` field.
- Relevant event patterns:

| Event | Raw message pattern |
|-------|---------------------|
| Failed login | `Failed password for <user> from <ip> port <port> ssh2` |
| Successful login | `Accepted password for <user> from <ip> port <port> ssh2` |
| Key-based login | `Accepted publickey for <user> from <ip> port <port> ssh2` |
| Invalid user | `Invalid user <user> from <ip> port <port>` |

---

## 3. Pivot into Kibana

Steps performed in Kibana:

1. Open **Discover** and select the `filebeat-*` data view.
2. Set the time range to **Last 24 hours** (expanded to see full attack context).
3. Run the following validation query to confirm failure events exist:

   ```kql
   message : "Failed password for"
   ```

4. Run the companion query to confirm success events exist:

   ```kql
   message : "Accepted password for"
   ```

5. Scope to the specific victim host:

   ```kql
   host.name : "ubuntu-victim" and message : "Failed password for"
   ```

6. Review the results and observe:
   - A clear spike of failed SSH messages around the time the attack ran.
   - A single `Accepted password for` event following the failures, confirming successful authentication.

---

## 4. Sample Event Review

Two key events were confirmed in Kibana during investigation:

**Failure event:**
```
@timestamp:          2026-05-12T11:41:30.477Z
host.name:           ubuntu-victim
log.file.path:       /var/log/auth.log
agent.name:          ubuntu-victim
message:             2026-05-12T11:41:26.426239+00:00 ubuntu-victim sshd[7579]: Failed password for jan from 172.16.0.11 port 52294 ssh2
```

**Success event:**
```
@timestamp:          2026-05-12T11:13:21.089Z
host.name:           ubuntu-victim
log.file.path:       /var/log/auth.log
agent.name:          ubuntu-victim
message:             2026-05-12T11:13:18.104652+00:00 ubuntu-victim sshd[1398]: Accepted password for kali from 172.16.0.11 port 45440 ssh2
```

Both events share the same source IP (`172.16.0.11`), confirming the attacker identity and the failure → success brute-force pattern.

---

## 5. Assessment

- The activity is consistent with a brute-force / password-guessing attack targeting SSH on a Linux host.
- The attacker successfully authenticated using a valid credential (`kali` user), indicating the attack was at least partially successful.
- The logging pipeline functioned as expected: `/var/log/auth.log` → Filebeat → Elasticsearch → Kibana.
- Broad KQL validation query returned **~948 events**, confirming high log volume and the need for scoped detection rules.
- ECS field parsing (`source.ip`, `user.name`, `event.outcome`) is **not present** — current detection relies on raw message string matching only.

---

## 6. Screenshots Collected

- `evidence/kibana-discover-failed-password-spike.png` – Discover view showing the `Failed password for` spike and event list.
- `evidence/kibana-discover-accepted-password.png` – Discover view showing the `Accepted password for` success event.
- `evidence/kibana-alerts-ssh-failed.png` – Alerts view showing triggered **"Linux SSH Failed Authentication Attempt"** alerts.
- `evidence/attacker-hydra-output.png` – Attacker terminal showing Hydra run with repeated SSH failures.

> Place these files under `incidents/INC-009-ssh-bruteforce/evidence/` when available.
