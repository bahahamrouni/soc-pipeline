# RULE_ID_MAP patch

Once rule 100201 (pfSense port scan correlation) exists on the Wazuh manager,
the AI inference service's RULE_ID_MAP must know about it, or detected scans
fall through as "unclassified" and never reach the classifier correctly.

Find the mapping in your soc-pipeline repo (likely in the inference service,
e.g. `services/ai-inference/rule_map.py` or similar — search for the existing
entries to confirm the exact file):

```bash
grep -rn "RULE_ID_MAP" soc-pipeline/
```

Add the new rule ID, mapped to whichever of your 8 attack classes covers
reconnaissance/port-scanning. Example (adjust class name to match your
existing taxonomy exactly):

```python
RULE_ID_MAP = {
    # ... existing entries ...
    100201: "reconnaissance",   # pfSense port scan correlation rule (new)
    5710:   "brute_force",      # confirm this already exists for SSH auth failures
    5712:   "brute_force",      # multiple SSH auth failures (if separate rule id used)
    # add hydra-specific rule id here once the hydra local_rules.xml rule is written
}
```

## Also confirm/add a hydra brute-force rule
Table 17 tests SSH brute force via hydra, but only the nmap rule is currently
documented in the appendix. Add this to local_rules.xml alongside the pfSense
rules (Wazuh's default sshd decoder already parses "Failed password" lines,
so this just adds frequency-based escalation on top of the existing base
rule — check your installed ruleset for the exact base sid with):

```bash
grep -rn "sshd" /var/ossec/ruleset/rules/*.xml | grep -i "failed password"
```

Then add a frequency rule referencing that base sid, e.g.:

```xml
<rule id="100210" level="10" frequency="6" timeframe="60">
  <if_matched_sid>5710</if_matched_sid>  <!-- confirm this is your actual base sid -->
  <same_source_ip />
  <description>SSH brute force: 6+ failed logins from $(srcip) in 60s</description>
  <mitre><id>T1110</id></mitre>
  <group>authentication_failures,brute_force,</group>
</rule>
```

Add `100210: "brute_force"` to RULE_ID_MAP as well.
