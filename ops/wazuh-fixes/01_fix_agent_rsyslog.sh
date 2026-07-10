#!/bin/bash
# Run as root on UBNT-WEB (192.168.10.104), the Debian agent whose auth
# events were only reaching journald (not visible to the Wazuh agent).
set -e

echo "[1/5] Installing rsyslog..."
apt-get update -qq
apt-get install -y rsyslog

echo "[2/5] Enabling journald -> syslog forwarding..."
if grep -q '^#\?ForwardToSyslog=' /etc/systemd/journald.conf; then
    sed -i 's/^#\?ForwardToSyslog=.*/ForwardToSyslog=yes/' /etc/systemd/journald.conf
else
    echo 'ForwardToSyslog=yes' >> /etc/systemd/journald.conf
fi

echo "[3/5] Restarting journald and enabling rsyslog..."
systemctl restart systemd-journald
systemctl enable --now rsyslog

echo "[4/5] Confirming Wazuh agent watches /var/log/auth.log..."
if ! grep -q "/var/log/auth.log" /var/ossec/etc/ossec.conf; then
    echo "  -> Not found. Adding <localfile> block."
    python3 - <<'PYEOF'
import re
path = "/var/ossec/etc/ossec.conf"
with open(path) as f:
    content = f.read()
block = "  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/auth.log</location>\n  </localfile>\n"
content = content.replace("</ossec_config>", block + "</ossec_config>", 1)
with open(path, "w") as f:
    f.write(content)
PYEOF
    systemctl restart wazuh-agent
else
    echo "  -> Already present, no change needed."
fi

echo "[5/5] Trigger a test event and verify it lands..."
logger "wazuh-fix-verification-test-$(date +%s)"
sleep 2
tail -n 3 /var/log/syslog 2>/dev/null || tail -n 3 /var/log/messages
echo ""
echo "Done. On the Wazuh manager, confirm the test event arrived with:"
echo "  tail -f /var/ossec/logs/alerts/alerts.json | grep wazuh-fix-verification-test"
