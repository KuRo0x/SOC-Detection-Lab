# INC-006: Lessons Learned

## What Worked Well

- **Multi-source detection** proved resilient: when Event 4698 was unavailable, Sysmon Event 1 telemetry provided full attack chain visibility
- **Correlation query** combining 4698 + Sysmon Event 1 gave a complete picture in a single Kibana search
- **Sigma rule validation** with `sigma-cli` caught formatting issues (UUID requirement, duplicate tags) before pushing to repo
- **Attack chain continuity** between INC-003 and INC-006 demonstrates realistic post-exploitation progression

---

## What Failed Initially

| Issue | Root Cause | Fix Applied |
|-------|------------|-------------|
| Event 4698 not firing | Windows audit policy requires kernel reload (reboot) to activate | Full VM reboot forced policy to take effect |
| `sigma check` UUID error | Rule ID was a custom string, not a valid UUID v4 | Generated proper UUID with `[guid]::NewGuid()` in PowerShell |
| Duplicate tag in Sigma rule | Multiple tag edits left duplicate `attack.t1053.005` entries | Rewrote file from scratch with single clean tags block |

---

## Key Takeaways

1. **Audit policy changes require a reboot** — always reboot after `auditpol` or `secpol.msc` changes in a lab environment
2. **Never rely on a single log source** — Event 4698 alone is insufficient; Sysmon process telemetry provides deeper forensic value
3. **Always validate Sigma rules** with `sigma check` before deploying — syntax errors can silently break detection
4. **Document detection gaps** — PowerShell task creation and remote task creation variants are not covered by this rule and require separate detection logic

---

## MITRE ATT&CK Coverage After INC-006

| ID | Technique | Covered |
|----|-----------|--------|
| T1566.002 | Phishing: Spearphishing Link | ✅ INC-001 |
| T1059.001 | PowerShell | ✅ INC-002 |
| T1136.001 | Create Account: Local Account | ✅ INC-003 |
| T1110.001 | Brute Force: Password Guessing | ✅ INC-004 |
| T1595.002 | Active Scanning: Vulnerability Scanning | ✅ INC-005 |
| T1053.005 | Scheduled Task/Job | ✅ INC-006 |
