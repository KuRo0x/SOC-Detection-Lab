# Suricata

> Network-based intrusion detection running on the SIEM VM. Monitors all traffic on the internal lab interface and generates structured alerts ingested by the ELK stack.

---

## Platform

| Field | Value |
|---|---|
| Version | 7.0.3 RELEASE |
| Host | soc-brn-ubn (Ubuntu SIEM VM) |
| Interface | ens33 |
| Mode | AF-Packet (passive IDS) |
| Service | enabled, active (running) |

---

## Network Variables

| Variable | Value | Meaning |
|---|---|---|
| HOME_NET | 172.16.0.0/24 | Internal lab network (VMnet3) |
| EXTERNAL_NET | !$HOME_NET | Everything outside the lab |

---

## Rule Sets

| Type | Location | Status |
|---|---|---|
| Default event rules | /etc/suricata/rules/ | Active (Suricata built-in) |
| Custom local rules | /etc/suricata/rules/local.rules | Not created yet |

### Default Rule Files
```
app-layer-events.rules
decoder-events.rules
dhcp-events.rules
dns-events.rules
files.rules
ftp-events.rules
http-events.rules
http2-events.rules
kerberos-events.rules
smb-events.rules
smtp-events.rules
ssh-events.rules
```

> Custom Suricata rules will be added to `local.rules` during adversary emulation scenarios and documented here.

---

## Alert Output

Suricata writes structured alerts to `eve.json` (Elastic Common Schema compatible), ingested by Logstash into Elasticsearch.

| Output | Format | Consumed By |
|---|---|---|
| /var/log/suricata/eve.json | JSON (ECS) | Logstash → Elasticsearch |

---

## Lab Role

- **Passive network monitoring** — inspects all traffic on ens33 without inline blocking
- **Alert generation** — detects known malicious patterns at the network layer
- **SIEM feed** — eve.json alerts flow into ELK for correlation with endpoint telemetry
- **Coverage gap filler** — catches threats that bypass endpoint detection
