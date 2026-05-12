# INC-009: Containment & Remediation

## Immediate Actions

### 1. Block the Attacker IP at the Firewall (pfSense)

In the lab, add the attacker IP to a pfSense block alias and create a LAN rule to deny SSH from it:

- Create alias `ATTACKER_SSH_BLOCK` → add `172.16.0.11`
- Add LAN rule: **Block TCP/22** from `ATTACKER_SSH_BLOCK` to `ubuntu-victim`

Once enabled, no new SSH connections from the attacker will succeed and no further `Failed password` events from that IP will appear in Kibana.

---

### 2. Lock or Disable Compromised Accounts

If a user account was successfully brute-forced (e.g. `kali`), immediately change its password or disable it:

```bash
# Change password
passwd kali

# Or disable the account entirely
usermod --expiredate 1 kali
# Re-enable later:
usermod --expiredate "" kali
```

---

### 3. Kill Active SSH Sessions from the Attacker

Identify and kill any live sessions from the attacker IP:

```bash
# Find active SSH sessions from attacker
who | grep -v localhost
ss -tnp | grep :22

# Kill the sshd process for the attacker session (replace PID)
kill -9 <sshd_pid>
```

---

### 4. Review Authorized Keys

If the attacker may have established persistence via SSH key, audit all authorized_keys files:

```bash
cat /root/.ssh/authorized_keys
cat /home/kali/.ssh/authorized_keys
ls -la /home/*/.ssh/
```

Remove any unauthorized keys immediately.

---

### 5. Verify No Cron Jobs or Backdoors Were Added

```bash
crontab -l
crontab -l -u kali
ls /etc/cron* /var/spool/cron/
```

---

## Post-Incident Hardening

### Disable Password Authentication for SSH
Force key-based authentication only by editing `/etc/ssh/sshd_config`:

```bash
PasswordAuthentication no
PermitRootLogin no
MaxAuthTries 3
```

Then restart sshd:
```bash
systemctl restart sshd
```

### Deploy fail2ban

Install and configure `fail2ban` to auto-ban IPs after repeated SSH failures:

```bash
apt install fail2ban
# /etc/fail2ban/jail.local
[sshd]
enabled = true
maxretry = 5
findtime = 300
bantime = 3600
```

### Restrict SSH Access by IP (AllowUsers / AllowGroups)

```bash
# /etc/ssh/sshd_config
AllowUsers admin@192.168.1.0/24
```

### Enable Two-Factor Authentication for SSH

Use `libpam-google-authenticator` or similar for SSH 2FA in production environments.
