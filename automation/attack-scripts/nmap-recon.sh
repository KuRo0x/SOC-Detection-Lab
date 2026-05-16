#!/bin/bash
# =============================================================================
# Script      : nmap-recon.sh
# Author      : KuRo (KuRo0x)
# Lab         : KuRo SOC Detection Lab
# Incident    : INC-005 — Nmap Reconnaissance
# Attacker VM : kali (172.16.0.11)
# Target      : VMnet3 subnet — 172.16.0.0/24
# Purpose     : Simulate network reconnaissance using Nmap to discover
#               live hosts and open ports across the isolated lab network.
#               Generates Suricata IDS alerts (ET SCAN rules) captured as
#               EVE JSON and forwarded to Elasticsearch (suricata-* index)
# Detection   : Suricata IDS — ET SCAN Nmap rules on pfSense (172.16.0.1)
# MITRE ATT&CK: T1046 — Network Service Discovery | TA0007 Discovery
# WARNING     : Run ONLY inside the isolated VMnet3 lab network (172.16.0.0/24)
# =============================================================================

SUBNET="172.16.0.0/24"
ATTACKER="172.16.0.11"

echo "[*] Starting Nmap reconnaissance against $SUBNET"
echo "[*] Attacker : $ATTACKER"
echo "[*] Expected : Suricata IDS alerts on pfSense (172.16.0.1)"
echo "[*] Expected index: suricata-* in Kibana"
echo ""

# Phase 1 — Host discovery
echo "[*] Phase 1: Host discovery"
nmap -sn "$SUBNET"

echo ""

# Phase 2 — Port scan on discovered hosts
echo "[*] Phase 2: Port + service scan on known lab hosts"
nmap -sV -sC -p 22,80,443,445,5044,5601,9200 \
     172.16.0.1 \
     172.16.0.4 \
     172.16.0.10 \
     172.16.0.20

echo ""
echo "[*] Scan complete. Check Kibana Discover:"
echo "    Index: suricata-*"
echo "    KQL  : event.module: \"suricata\" and source.ip: \"172.16.0.11\""
echo "    Rule : Suricata IDS — ET SCAN category alerts"
