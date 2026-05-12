# INC-009: Lessons Learned

## What Happened

An attacker from `172.16.0.11` (Kali Linux) launched a brute-force password attack against SSH (TCP 22) on `ubuntu-victim`. After cycling through multiple usernames and passwords, a valid credential was found and a successful SSH session was established using the `kali` account.

The attack succeeded because:
- SSH password authentication was enabled on the victim host
- No rate-limiting or lockout mechanism (`fail2ban`) was in place
- The `kali` account used a weak or commonly known password
- No alerting was configured to notify the analyst in real time

---

## Why SSH Brute Force Works

SSH with password authentication simply accepts repeated login attempts. Without rate-limiting, an attacker with a wordlist can try thousands of passwords per minute:

```
Attacker → hydra → 172.16.0.11:22 → Failed password (repeat N times) → Accepted password
```

Unlike Windows account lockout policies, Linux SSH does not have a built-in lockout by default.

---

## Detection Gap — No ECS Field Parsing

The most significant detection gap discovered in this incident is that Filebeat ingests SSH auth log events as **raw text only**. Fields like `source.ip`, `user.name`, `event.outcome`, and `event.category` are not parsed, which means:

- EQL sequence rules cannot be used (require structured fields)
- Alert suppression by `source.ip` is not possible
- Correlation across events (e.g. same IP, multiple users) requires manual analysis

**Recommended fix:** Add an Elasticsearch ingest pipeline or Logstash grok filter to extract ECS fields from SSH messages. See `improvements.md` for the full grok patterns.

---

## Detection Summary

| Signal | Field / Query | Value |
|--------|--------------|-------|
| SSH failure | `message : "Failed password for"` | High volume from `172.16.0.11` |
| SSH success | `message : "Accepted password for"` | Single event — `kali` user |
| Invalid user | `message : "Invalid user"` | Multiple unknown usernames tried |
| Kibana events total | Broad query result | ~948 events |
| Host | `host.name` | `ubuntu-victim` |
| Attacker IP | Raw message | `172.16.0.11` |

---

## Prevention

| Control | Action |
|---------|--------|
| Disable password auth | Set `PasswordAuthentication no` in `/etc/ssh/sshd_config` |
| Deploy fail2ban | Auto-ban IPs after N failures in a time window |
| Use strong passwords | Enforce complexity; avoid default/well-known passwords |
| Rotate credentials | Change passwords regularly for all SSH-accessible accounts |
| Restrict SSH by IP | Use `AllowUsers`, firewall rules, or VPN-only access |
| Enable 2FA for SSH | Add TOTP second factor via PAM |
| Alert on failures | Wire Elastic Security rule to email/webhook connector |
| Parse ECS fields | Add ingest pipeline so `source.ip` and `user.name` are indexed |

---

## Lab Notes

- Password authentication was intentionally enabled on `ubuntu-victim` for the lab exercise — **must be disabled in production**
- The `kali` user exists on the victim as a lab account — this would not be present in a hardened environment
- The attack chain is a classic **T1110.001 – Password Guessing** scenario that translates directly to real-world SSH exposure
- Filebeat successfully captured all auth events but the lack of ECS parsing is a real gap that limits detection capabilities
- The broad KQL query returned ~948 events, highlighting the importance of scoped rules and field-level suppression
