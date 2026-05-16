# Threat Intelligence

This folder contains IOC lists, threat intelligence feeds, and threat context used for detection enrichment in the KuRo SOC Detection Lab.

---

## Lab IOC Summary

| IOC Type | Value | Source Incident | Status |
|---|---|---|---|
| Attacker IP | `172.16.0.11` | All incidents | Internal lab |
| SSH brute-force user | `jan`, `kali` | INC-009 | Lab simulated |
| sshd PID (failure) | `7579` | INC-009 | Lab simulated |
| sshd PID (success) | `1398` | INC-009 | Lab simulated |

---

## Hunt Queries — IOC-Based

```kql
# All traffic from attacker IP across all indices
message : "172.16.0.11"

# SSH IOCs from INC-009
message : "172.16.0.11" and message : ("Failed password" or "Accepted password" or "Invalid user")
```

---

## Planned — External TI Integration

- Pull daily IOC feeds from [Abuse.ch](https://abuse.ch/) (MalwareBazaar, URLhaus, Feodo)
- Enrich Suricata alerts with VirusTotal hash lookups
- Add `threat.indicator` ECS fields via Logstash enrichment filter

> Add IOC lists and feed configs here as the lab expands.
