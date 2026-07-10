#!/usr/bin/env python3
"""
Ground-truth run logger.

Usage (run from Kali or wherever you launch attacks, one call per execution):

    python3 06_run_logger.py --scenario RECON-01 --class reconnaissance \
        --cmd "nmap -sV -p- 192.168.10.104" --target 192.168.10.104

It runs the given command, times it, and appends one row to run_log.csv with
the exact start/end timestamps. That file is the ground truth used later to
label alerts captured in the same window (see 07_build_labeled_dataset.py).

For BENIGN windows, don't run a command — just log the window manually:

    python3 06_run_logger.py --scenario BENIGN-01 --class benign \
        --manual --duration-hours 5
"""
import argparse
import csv
import os
import subprocess
import time
from datetime import datetime, timezone

LOG_PATH = "run_log.csv"


def append_row(row):
    exists = os.path.exists(LOG_PATH)
    with open(LOG_PATH, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "scenario_id", "attack_class", "tool_cmd", "target",
            "start_time_utc", "end_time_utc", "run_note"
        ])
        if not exists:
            w.writeheader()
        w.writerow(row)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--class", dest="attack_class", required=True)
    ap.add_argument("--cmd", default="")
    ap.add_argument("--target", default="")
    ap.add_argument("--manual", action="store_true",
                     help="don't execute a command, just log a manual window")
    ap.add_argument("--duration-hours", type=float, default=0)
    ap.add_argument("--note", default="")
    args = ap.parse_args()

    start = datetime.now(timezone.utc)

    if args.manual:
        print(f"Manual window started at {start.isoformat()}.")
        print(f"Leave this process running for the benign period, "
              f"then Ctrl+C (or wait {args.duration_hours}h) to close it out.")
        try:
            if args.duration_hours > 0:
                time.sleep(args.duration_hours * 3600)
            else:
                while True:
                    time.sleep(60)
        except KeyboardInterrupt:
            pass
    else:
        if not args.cmd:
            raise SystemExit("--cmd required unless --manual")
        print(f"[{start.isoformat()}] Running: {args.cmd}")
        subprocess.run(args.cmd, shell=True)

    end = datetime.now(timezone.utc)
    append_row({
        "scenario_id": args.scenario,
        "attack_class": args.attack_class,
        "tool_cmd": args.cmd if args.cmd else "manual/benign",
        "target": args.target,
        "start_time_utc": start.isoformat(),
        "end_time_utc": end.isoformat(),
        "run_note": args.note,
    })
    print(f"Logged {args.scenario} [{start.isoformat()} -> {end.isoformat()}] to {LOG_PATH}")


if __name__ == "__main__":
    main()
