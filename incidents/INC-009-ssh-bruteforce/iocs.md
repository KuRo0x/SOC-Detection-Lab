# INC-009: Indicators of Compromise

## Network IOCs

| Type | Value | Notes |
|------|-------|-------|
| Attacker IP | `172.16.0.11` | Kali Linux attacker VM |
| Victim IP | `172.16.0.x` | ubuntu-victim |
| Protocol | SSH (TCP 22) | Used for brute-force |
| SSH Flow | `172.16.0.11 → ubuntu-victim:22` | Repeated failed auth attempts |
| Source port range | ephemeral (e.g. 45440, 52294) | Cycling ports per SSH attempt |

---

## Host IOCs

| Type | Value | Notes |
|------|-------|-------|
| Targeted user(s) | `jan`, `kali` (and others) | Usernames seen in auth log failures |
| Successful user | `kali` | Account used in confirmed successful login |
| Log file | `/var/log/auth.log` | Source of all SSH auth events |
| sshd PID | `7579` (failure), `1398` (success) | Seen in raw message fields |

---

## Log IOCs

| Event type | Raw message pattern |
|------------|---------------------|
| Password failure | `Failed password for <user> from 172.16.0.11 port <port> ssh2` |
| Successful login | `Accepted password for kali from 172.16.0.11 port 45440 ssh2` |
| Invalid user | `Invalid user <user> from 172.16.0.11 port <port>` |
| Publickey failure | `Failed publickey for <user> from 172.16.0.11 port <port> ssh2` |

**Confirmed events from lab:**
```
2026-05-12T11:41:26+00:00 ubuntu-victim sshd[7579]: Failed password for jan from 172.16.0.11 port 52294 ssh2
2026-05-12T11:13:18+00:00 ubuntu-victim sshd[1398]: Accepted password for kali from 172.16.0.11 port 45440 ssh2
```

---

## Tool

| Tool | Notes |
|------|-------|
| `hydra` | SSH brute-force tool used by attacker (Kali Linux) |
| `ssh` (manual) | Manual SSH attempts also observed |

---

## Kibana Hunt Queries

**Hunt for attacker IP across all auth events:**
```kql
message : "172.16.0.11" and message : ("Failed password" or "Accepted password" or "Invalid user")
```

**Hunt for successful logins from attacker IP:**
```kql
message : "172.16.0.11" and message : "Accepted password for"
```
