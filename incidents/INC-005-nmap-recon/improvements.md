# INC-005 – Improvements & Lessons Learned


## Detection Gaps Analysis

| # | Gap | What It Misses | Root Cause | Fix |
|---|---|---|---|---|
| 1 | No Suricata deployed in this lab at time of scan | Entire network IDS layer absent | Lab configuration gap | Deploy Suricata on pfSense or as inline sensor |
| 2 | No SYN rate baseline established before incident | Alert threshold set without baseline | No baseline measurement | Run 7-day passive collection; set threshold at mean + 3σ |
| 3 | Sysmon Event ID 3 was present but no alert rule existed | 20 inbound connections logged — no automated alert fired | No detection rule on burst | Create Elastic threshold rule: >10 unique destination ports from one source in 60 seconds |
| 4 | Suricata ET SCAN misses slow-and-low scans | Evasion-aware attacker spreading probes over hours would not trigger | Rate-based signatures only | Add long-window aggregation rule: >50 unique destination ports over 10 minutes |
| 5 | No automated IP block on alert trigger | Manual response added ~2 minutes of exposure | No SOAR/response action | Integrate pfSense REST API with Elastic response actions |
| 6 | RDP (3389) and SMB (445) found exposed through this scan | High-value services reachable with no prior awareness | No scheduled firewall audit | Monthly `nmap -sS --open` audit from WAN-side VM |
| 7 | No GeoIP / ASN enrichment on firewall logs | Source IP context not immediately visible | Logstash pipeline not enriched | Enable MaxMind GeoLite2 filter in Logstash |


## Impact Assessment

### Finding 1 — RDP (3389) Exposed
- **Microsoft Terminal Services** confirmed open and responding (Nmap `-sV` + Sysmon Event ID 3 at 03:06:50)
- **Blast radius:** Complete host compromise — file access, credential dumping, lateral movement, ransomware deployment

### Finding 2 — SMB (445) Exposed → Direct Link to INC-004
- Kill chain confirmed:
  ```
  INC-005 (Recon) → INC-004 (SMB Brute Force) → Potential Remote Access
  ```

### Risk Rating

| Service | Exposure | Combined Risk |
|---|---|---|
| RDP (3389) | External | **CRITICAL** |
| SMB (445) | External | **CRITICAL** |
| NetBIOS (139) | External | **HIGH** |
| MSRPC (135) | External | **MEDIUM** |


## Containment Actions

### Immediate Response (0–15 minutes)

| Action | Lab (what was done) | Real Environment |
|---|---|---|
| **Block source IP** | Added `172.16.0.11` to `ATTACKER_RECON_BLOCK` in pfSense manually | Automated via Elastic response action → pfSense REST API |
| **Preserve evidence** | Nmap outputs saved to `evidence/`; Kibana screenshots taken | Packet capture preserved; logs exported and hashed (SHA256) |

### Short-Term Remediation (15 min – 24 hours)

1. **Restrict RDP (3389):** Allow only from `RFC1918_INTERNAL` alias.
2. **Restrict SMB (445):** Block at perimeter, allow only trusted subnets.
3. **Restrict NetBIOS (139):** Block entirely unless legacy dependency confirmed.
4. **Enable SYN cookies** on pfSense.
5. **Add rate-limiting rule** in pfSense: Max 100 new connections/s per source IP.
6. **Review auth logs** on `DESKTOP-DPU3CDQ` for login attempts from `172.16.0.11`.

### Long-Term Hardening (24–72 hours)

1. **Network segmentation:** Move RDP and SMB to management VLAN, accessible only via jump host/VPN.
2. **Deploy Sysmon on all Windows hosts** with SwiftOnSecurity baseline config.
3. **Deploy Suricata** on pfSense or dedicated sensor.
4. **Enable NLA on RDP** — requires credentials before RDP session establishment.
5. **Implement account lockout** on Windows: 5 failed attempts → 15 min lockout.
6. **Deploy Elastic SOAR response action** for automatic pfSense block on alert.


## What Worked

- Sysmon Event ID 3 on the victim corroborated the attacker-side scan — cross-source correlation confirmed the scan from two independent data sources.
- The Sysmon RDP probe log (03:06:50) provided exact timestamp alignment with Nmap Stage 3.
- Kill chain link to INC-004 was identified through port correlation.


## Lessons Learned

### One-liner for the portfolio
> A fast Nmap scan is loud and easy to catch. The real detection challenge is the slow scan that takes 10 minutes instead of 45 seconds — and the real detection gap is the missing alert rule that should have fired automatically on the Sysmon spike.

### References

- [MITRE ATT&CK T1595.001](https://attack.mitre.org/techniques/T1595/001/)
- [MITRE ATT&CK T1595.002](https://attack.mitre.org/techniques/T1595/002/)
- [Nmap Evasion Techniques](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [Suricata ET SCAN Ruleset](https://rules.emergingthreats.net/)
- [Sigma Rule Repository](https://github.com/SigmaHQ/sigma)