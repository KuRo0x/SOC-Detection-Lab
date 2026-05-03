# Containment

## Network Containment
The phishing infrastructure was hosted on a Kali Linux VM within the lab environment. Following detection, outbound communication from the victim LAN to the attacker infrastructure was blocked to prevent payload retrieval and follow-up communication.

## Firewall Actions
- Created firewall alias: `ATTACKER_KALI_INC001`
- Alias contained validated attacker IP(s)
- Implemented LAN rule blocking TCP ports 80 and 443
- Logging enabled to confirm enforcement

## Result
- Outbound communication to attacker infrastructure successfully blocked
- No further download or callback activity observed

## Evidence
- Firewall alias config: [`evidence/firewall/pfsense-alias-attacker-inc001.png`](evidence/firewall/pfsense-alias-attacker-inc001.png)
- Firewall LAN block rule: [`evidence/firewall/pfsense-lan-block-rule-inc001.png`](evidence/firewall/pfsense-lan-block-rule-inc001.png)
