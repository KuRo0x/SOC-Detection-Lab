# INC-008: Lessons Learned

## What Happened

After stealing the NTLM hash of `END-Alex` in INC-007, the attacker reused it without knowing the plaintext password. This is **Pass-the-Hash (PtH)** — a classic lateral movement technique that bypasses password authentication entirely by replaying the hash directly against NTLM.

The attack succeeded because:
- The hash was never rotated after INC-007
- Remote UAC token filtering was disabled (`LocalAccountTokenFilterPolicy=1`)
- Windows Defender was not blocking the attack in time
- `END-Alex` was a local admin with full access to `ADMIN$`

---

## Why PtH Works

NTLM authentication uses the hash as a **proof of identity** — if you have the hash, Windows accepts it as the user. There is no challenge that requires the original password.

```
User → Hash → NTLM Challenge/Response → Access Granted
Attacker → Same Hash → Same Challenge/Response → Same Access
```

---

## Prevention

| Control | Action |
|---|---|
| Rotate credentials immediately | Change password right after any credential dump |
| Keep Remote UAC enabled | Do NOT set `LocalAccountTokenFilterPolicy=1` in production |
| Enable LSA Protection | `RunAsPPL=1` prevents credential dump in the first place |
| Reduce local admin accounts | Fewer admins = smaller PtH attack surface |
| Monitor 4624 + LogonType 3 + NTLM | Alert on network NTLM logons |
| Monitor Event 7045 | Alert on new service installations |
| Block NTLM where possible | Force Kerberos via Group Policy |
| Enable Credential Guard | Isolates NTLM hash in hypervisor-protected memory |

---

## Detection Summary

| Signal | Event ID | Field |
|---|---|---|
| Network logon | 4624 | LogonType=3, AuthPackage=NTLM |
| Remote service drop | 7045 | ServiceName=random |
| Defender alert | N/A | HackTool:Win32/Psexec!mclg |

---

## Lab Notes

- `LocalAccountTokenFilterPolicy` was intentionally set to `1` for the lab — **must be reverted in production**
- Windows Defender successfully detected `HackTool:Win32/Psexec!mclg` twice before the shell succeeded
- The attack chain INC-007 → INC-008 demonstrates real-world credential reuse and lateral movement
