#!/usr/bin/env python3
"""
Joins captured Wazuh alerts against run_log.csv time windows to produce a
labeled dataset for training. Run this on the Wazuh manager (UBNT24) after
executing all scenarios in 05_attack_test_matrix.csv via 06_run_logger.py.

Usage:
    python3 07_build_labeled_dataset.py \
        --alerts /var/ossec/logs/alerts/alerts.json \
        --run-log run_log.csv \
        --out labeled_dataset.csv \
        --pad-seconds 5

--pad-seconds adds a small buffer before/after each logged window to catch
alerts with slight timing lag (Wazuh processing delay, clock drift, etc).
Alerts outside any run window and outside any benign window are dropped —
they're neither confirmed attack nor confirmed benign, so including them
would introduce label noise.
"""
import argparse
import csv
import json
from datetime import datetime, timedelta, timezone


def parse_alert_time(alert):
    # Wazuh alerts.json timestamp field, format varies slightly by version
    ts = alert.get("timestamp") or alert.get("@timestamp")
    if ts is None:
        return None
    ts = ts.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def load_runs(path, pad_seconds):
    runs = []
    with open(path) as f:
        for row in csv.DictReader(f):
            start = datetime.fromisoformat(row["start_time_utc"]) - timedelta(seconds=pad_seconds)
            end = datetime.fromisoformat(row["end_time_utc"]) + timedelta(seconds=pad_seconds)
            runs.append({
                "scenario_id": row["scenario_id"],
                "attack_class": row["attack_class"],
                "target": row["target"],
                "start": start,
                "end": end,
            })
    return runs


def label_for(alert_time, alert_srcip, runs):
    # match on time window; if multiple runs targeted different hosts in an
    # overlapping window, prefer a run whose target matches the alert's srcip
    # /agent so concurrent unrelated runs don't cross-contaminate labels.
    candidates = [r for r in runs if r["start"] <= alert_time <= r["end"]]
    if not candidates:
        return None, None
    if len(candidates) > 1 and alert_srcip:
        for r in candidates:
            if r["target"] and r["target"] in alert_srcip:
                return r["attack_class"], r["scenario_id"]
    return candidates[0]["attack_class"], candidates[0]["scenario_id"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", required=True)
    ap.add_argument("--run-log", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--pad-seconds", type=float, default=5)
    args = ap.parse_args()

    runs = load_runs(args.run_log, args.pad_seconds)
    print(f"Loaded {len(runs)} ground-truth run windows.")

    matched, skipped = 0, 0
    out_rows = []

    with open(args.alerts, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            atime = parse_alert_time(alert)
            if atime is None:
                skipped += 1
                continue

            srcip = (alert.get("data", {}) or {}).get("srcip", "")
            label, scenario_id = label_for(atime, srcip, runs)
            if label is None:
                skipped += 1
                continue

            rule = alert.get("rule", {}) or {}
            agent = alert.get("agent", {}) or {}
            out_rows.append({
                "label": label,
                "scenario_id": scenario_id,
                "rule_id": rule.get("id", ""),
                "rule_level": rule.get("level", ""),
                "rule_description": rule.get("description", ""),
                "rule_groups": "|".join(rule.get("groups", []) or []),
                "agent_id": agent.get("id", ""),
                "agent_name": agent.get("name", ""),
                "srcip": srcip,
                "dstuser": (alert.get("data", {}) or {}).get("dstuser", ""),
                "timestamp": atime.isoformat(),
            })
            matched += 1

    if out_rows:
        with open(args.out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()))
            w.writeheader()
            w.writerows(out_rows)

    print(f"Matched {matched} alerts to a labeled run window, skipped {skipped}.")
    print(f"Wrote {args.out}")
    if matched == 0:
        print("WARNING: zero matches. Check that run_log.csv timestamps are "
              "UTC and overlap the alerts.json timerange, and that alerts "
              "are actually being generated (see 03_pfsense_setup.md step 4).")


if __name__ == "__main__":
    main()
