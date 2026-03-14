# Incident Response Playbook — Phishing Delivery

## Trigger
- Detection of suspicious browser download artifacts
- Defender or Elastic alert on `.crdownload` or `Zone.Identifier`

## Triage
1. Validate file type and download location
2. Identify initiating process and user context
3. Confirm no execution events in ±10 min window

## Investigation
1. Review Sysmon file creation and alternate data stream events
2. Check for execution or persistence indicators
3. Correlate with network activity (pfSense logs)

## Containment
1. Create firewall alias with attacker IP(s)
2. Block outbound TCP 80 and 443 to attacker infrastructure
3. Enable logging to confirm enforcement

## Recovery
- No recovery required if no execution observed
- Confirm file was blocked or removed

## Improvements
- Promote validated IOCs to persistent blocklists
- Update detection logic if new delivery pattern observed
