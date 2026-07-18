#!/bin/bash
set -euo pipefail

RULES_FILE="/var/ossec/etc/rules/local_rules.xml"
BACKUP_FILE="/var/ossec/etc/rules/local_rules.xml.bak.$(date +%Y%m%d%H%M%S)"
RULE_ID="100300"

echo "[*] Backing up $RULES_FILE -> $BACKUP_FILE"
cp "$RULES_FILE" "$BACKUP_FILE"

if grep -q "id=\"$RULE_ID\"" "$RULES_FILE"; then
    echo "[!] Rule id=$RULE_ID already present in $RULES_FILE — skipping insertion."
else
    echo "[*] Appending rule $RULE_ID (Windows event 4672 - privilege escalation)"
    cat >> "$RULES_FILE" << 'EOF'

<group name="windows,privilege_escalation,">

  <rule id="100300" level="10">
    <if_sid>60001</if_sid>
    <field name="win.system.eventID">^4672$</field>
    <description>Windows: special privileges assigned to new logon (SeDebugPrivilege/SeTakeOwnershipPrivilege) - possible privilege escalation</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>privilege_escalation,windows_security,</group>
  </rule>

</group>
EOF
fi

echo "[*] Validating rules via wazuh-analysisd test mode"
if ! /var/ossec/bin/wazuh-analysisd -t 2>/tmp/wazuh_test_err.txt; then
    echo "[X] Wazuh rule validation FAILED. Restoring backup."
    cat /tmp/wazuh_test_err.txt
    cp "$BACKUP_FILE" "$RULES_FILE"
    exit 1
fi
echo "[OK] Wazuh rules are valid."
echo "[*] Restarting wazuh-manager"
systemctl restart wazuh-manager

sleep 3
echo "[*] Checking manager status"
systemctl is-active --quiet wazuh-manager && echo "[OK] wazuh-manager is active" || {
    echo "[X] wazuh-manager failed to start. Check /var/ossec/logs/ossec.log"
    exit 1
}

echo "[*] Tailing ossec.log for rule-load confirmation / errors"
tail -n 30 /var/ossec/logs/ossec.log