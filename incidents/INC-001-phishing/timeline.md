# Incident Timeline

> All timestamps are approximate and based on Sysmon/Elastic event log data from the lab environment.

| Timestamp (UTC) | Event |
|---|---|
| 2025-01-15 14:00:00 | Phishing email delivered to victim mailbox |
| 2025-01-15 14:03:21 | User clicked malicious link in email via Microsoft Edge (`msedge.exe`) |
| 2025-01-15 14:03:24 | Browser initiated download — `.crdownload` artifact created on disk |
| 2025-01-15 14:03:25 | `Zone.Identifier` alternate data stream written — confirms internet-origin file |
| 2025-01-15 14:03:27 | Microsoft Defender detected malicious file — download blocked before execution |
| 2025-01-15 14:05:10 | Analyst identified alert in Elastic SIEM via KQL query (`event.original:*crdownload*`) |
| 2025-01-15 14:08:45 | pfSense firewall alias `ATTACKER_KALI_INC001` created with attacker IP |
| 2025-01-15 14:09:02 | LAN outbound rule applied — TCP 80 and 443 blocked to attacker infrastructure |
| 2025-01-15 14:15:00 | Firewall logs reviewed — no further outbound activity confirmed |
| 2025-01-15 14:20:00 | Incident closed — delivery-stage only, no execution or persistence observed |
