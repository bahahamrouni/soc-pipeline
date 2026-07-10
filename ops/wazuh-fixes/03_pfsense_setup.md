# pfSense -> Wazuh Syslog Forwarding Setup

## 1. pfSense side (GUI)
1. Log in to https://192.168.100.1
2. Go to **Status > System Logs > Settings**
3. Under "Remote Logging Options":
   - Check **Send log messages to remote syslog server(s)**
   - Under "Remote log servers" enter: `192.168.10.10:514`  (Wazuh manager, VLANSERVER-routable)
   - Under "Remote Syslog Contents" check at minimum:
     - Firewall Events
     - System Events (optional, useful for auth/config-change visibility)
   - Leave transport as UDP (matches the Wazuh <remote> block below)
4. Save.

## 2. Wazuh manager side (UBNT24, /var/ossec/etc/ossec.conf)
Add this block inside <ossec_config>, alongside the existing <remote> blocks
(don't remove the existing agent-connection remote block):

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.168.10.254</allowed-ips>  <!-- pfSense VLANSERVER interface -->
</remote>
```

Then:
```bash
/var/ossec/bin/wazuh-control restart
```

## 3. Install the decoder + rule
Append the two blocks from `02_pfsense_wazuh_decoder_rules.xml` into:
  - /var/ossec/etc/decoders/local_decoder.xml  (decoder section)
  - /var/ossec/etc/rules/local_rules.xml       (rule section)

Validate syntax before restarting:
```bash
/var/ossec/bin/wazuh-logtest-legacy   # or wazuh-logtest depending on version
```
Paste a captured filterlog line and confirm it decodes with the expected
fields (interface, action, protocol, srcip, dstip, srcport, dstport) before
moving on. Then:
```bash
/var/ossec/bin/wazuh-control restart
```

## 4. Verify end to end
From Kali, run a quick scan against a blocked port/host so pfSense logs a
block event:
```bash
nmap -p 1-100 192.168.10.104
```
Then check:
```bash
tail -f /var/ossec/logs/alerts/alerts.json | grep -i port_scan
```
You should see rule 100201 firing. If nothing appears, check in order:
1. Is pfSense actually sending? `tcpdump -i any port 514` on UBNT24.
2. Is the decoder matching? `wazuh-logtest` with a real captured line.
3. Is the rule's `<field name="action">block</field>` matching your decoder's
   field name/value exactly (case-sensitive) — adjust if your filterlog
   action field renders differently (e.g. "b" instead of "block" on some
   pfSense versions; check with logtest and adjust the regex/field value).
