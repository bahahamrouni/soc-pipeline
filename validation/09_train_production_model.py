#!/usr/bin/env python3
"""
Builds a REAL training set using the SAME 9-feature schema the production
ai-inference service actually uses (RULE_ID_MAP / SEVERITY_MAP / ROLE_MAP,
see services/ai-inference/ai_inference_service.py), by pulling real
incidents out of PostgreSQL and matching them against the ground-truth
run log (same time-window approach as 07_build_labeled_dataset.py).

This exists because 08_train_evaluate.py trains on a DIFFERENT, incompatible
4-feature schema derived from raw Wazuh alert fields (rule_id/agent_name/
rule_groups/rule_level via ad-hoc LabelEncoders that are never even saved).
That model cannot be loaded by the production service, which expects the
9-feature vector produced by extract_features() below. This script produces
a model file the production service can actually load as-is, and reports
an honest, held-out evaluation for THIS specific feature schema rather than
assuming the 08_train_evaluate.py macro-F1 (0.633) carries over unchanged.

IMPORTANT: extract_features() here is a deliberate, exact copy of the
function in services/ai-inference/ai_inference_service.py. If that function
ever changes, this one must be updated to match, or the resulting model
will silently misinterpret its own training features. This duplication is
a known limitation, not an oversight; see the PTI for the recommended
follow-up (share this logic from one place instead of two).

Usage:
    pip install psycopg2-binary xgboost scikit-learn pandas --break-system-packages
    python3 09_train_production_model.py \
        --run-log run_log.csv \
        --pg-host localhost --pg-db socdb --pg-user socuser --pg-password ... \
        --out xgboost_model.pkl
"""
import argparse
import csv
import json
import pickle
from collections import Counter
from datetime import datetime, timedelta, timezone

import numpy as np
import psycopg2
import psycopg2.extras
import xgboost as xgb
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import GroupShuffleSplit, train_test_split, StratifiedKFold, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, f1_score

# Exact copy of production's feature-mapping constants
# (services/ai-inference/ai_inference_service.py)
RULE_ID_MAP = {
    "CORR-001": 1,
    "CORR-002": 2,
    "CORR-003": 3,
    "CORR-004": 4,
    "CORR-005": 5,
    "CORR-006": 6,
}
SEVERITY_MAP = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
ROLE_MAP = {
    "unknown": 0,
    "workstation": 1,
    "web-server": 2,
    "file-server": 3,
    "db-server": 4,
    "siem-server": 5,
}


def extract_features(incident):
    """Exact copy of AttackClassifier.extract_features() in
    ai_inference_service.py. Must be kept in sync with that function."""
    rule_id = RULE_ID_MAP.get(
        incident.get("correlation_rule", {}).get("id", ""), 0
    )
    severity = SEVERITY_MAP.get(
        incident.get("severity", "medium"), 2
    )
    event_count = incident.get("event_count", 1)
    window_sec = incident.get("correlation_rule", {}).get("window_sec", 60)
    threshold = incident.get("correlation_rule", {}).get("threshold", 5)

    ta = incident.get("triggering_alert", {})
    asset = ta.get("asset", {})
    criticality = int(asset.get("criticality") or 1)
    role = ROLE_MAP.get(asset.get("role", "unknown"), 0)

    src_ip = ta.get("source", {}).get("ip", "unknown") or "unknown"
    internal = 1 if src_ip.startswith("192.168.") else 0

    try:
        ts = incident.get("@timestamp", "")
        hour = datetime.fromisoformat(ts.replace("Z", "+00:00")).hour
    except Exception:
        hour = 12

    return [rule_id, severity, event_count, window_sec,
            threshold, criticality, role, internal, hour]


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
                "run_id": f"{row['scenario_id']}__{row['start_time_utc']}",
            })
    return runs


def label_for(ts, srcip, runs):
    """Returns (attack_class, run_id) or (None, None) if no window matches."""
    candidates = [r for r in runs if r["start"] <= ts <= r["end"]]
    if not candidates:
        return None, None
    if len(candidates) > 1 and srcip:
        for r in candidates:
            if r["target"] and r["target"] in srcip:
                return r["attack_class"], r["run_id"]
    return candidates[0]["attack_class"], candidates[0]["run_id"]


def try_group_split(X, y, groups, n_classes):
    """Attempt a leakage-safe group split; return None if any class ends up
    missing from train or test (mirrors 08_train_evaluate.py's approach)."""
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(gss.split(X, y, groups))
    if len(np.unique(y[train_idx])) < n_classes or len(np.unique(y[test_idx])) < n_classes:
        return None
    return train_idx, test_idx


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-log", required=True)
    ap.add_argument("--pad-seconds", type=float, default=5)
    ap.add_argument("--pg-host", required=True)
    ap.add_argument("--pg-port", default=5432, type=int)
    ap.add_argument("--pg-db", required=True)
    ap.add_argument("--pg-user", required=True)
    ap.add_argument("--pg-password", required=True)
    ap.add_argument("--out", default="xgboost_model.pkl")
    args = ap.parse_args()

    runs = load_runs(args.run_log, args.pad_seconds)
    print(f"Loaded {len(runs)} ground-truth run windows.")

    conn = psycopg2.connect(
        host=args.pg_host, port=args.pg_port, dbname=args.pg_db,
        user=args.pg_user, password=args.pg_password,
    )
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id, first_seen, raw_incident FROM incidents ORDER BY first_seen")
    rows = cur.fetchall()
    print(f"Fetched {len(rows)} incidents from PostgreSQL.")

    X, y, groups = [], [], []
    matched, skipped = 0, 0
    for row in rows:
        raw = row["raw_incident"]
        if isinstance(raw, str):
            raw = json.loads(raw)
        ts = row["first_seen"]
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        srcip = raw.get("triggering_alert", {}).get("source", {}).get("ip", "")
        label, run_id = label_for(ts, srcip, runs)
        if label is None:
            skipped += 1
            continue
        X.append(extract_features(raw))
        y.append(label)
        groups.append(run_id)
        matched += 1

    print(f"Matched {matched} incidents to a labeled run window, skipped {skipped}.")
    if matched == 0:
        print("ERROR: no incidents matched. Check that PostgreSQL actually "
              "contains incidents from the same attack runs as run_log.csv, "
              "and that timestamps are in the expected range.")
        return

    print("Class distribution:", Counter(y))
    print("Distinct independent runs (groups):", len(set(groups)))

    X = np.array(X, dtype=np.float32)
    groups = np.array(groups)
    label_encoder = LabelEncoder()
    y_enc = label_encoder.fit_transform(y)
    n_classes = len(label_encoder.classes_)

    # Leakage-safe evaluation split, with stratified fallback
    result = try_group_split(X, y_enc, groups, n_classes)
    if result is not None:
        train_idx, test_idx = result
        split_method = "grouped by run_id"
    else:
        print("\nWARNING: not enough independent runs per class for a safe "
              "grouped split (a class collected as one continuous run cannot "
              "itself be subdivided). Falling back to a stratified per-"
              "incident split. LIMITATION: incidents from the same run may "
              "appear in both train and test for under-represented classes, "
              "which can inflate their reported metrics.")
        all_idx = np.arange(len(X))
        train_idx, test_idx = train_test_split(
            all_idx, test_size=0.2, random_state=42, stratify=y_enc)
        split_method = "stratified per-incident (grouped split not viable)"

    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y_enc[train_idx], y_enc[test_idx]

    print(f"\nSplit method: {split_method}")
    print(f"Split sizes -> train: {len(X_train)}, test: {len(X_test)}")

    min_class_count = min(Counter(y_train).values())
    n_splits = max(2, min(5, min_class_count))
    if n_splits < 5:
        print(f"NOTE: smallest class in training set has only {min_class_count} "
              f"sample(s) - using {n_splits}-fold CV instead of 5-fold.")

    param_grid = {
        "max_depth": [4, 6, 8],
        "learning_rate": [0.05, 0.1, 0.2],
        "n_estimators": [100, 200],
    }
    base_model = xgb.XGBClassifier(eval_metric="mlogloss", random_state=42)
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    search = GridSearchCV(base_model, param_grid, cv=skf, scoring="f1_macro", n_jobs=-1)
    search.fit(X_train, y_train)
    eval_model = search.best_estimator_
    print(f"Best params: {search.best_params_}")

    y_pred = eval_model.predict(X_test)
    print("\n=== Classification report (held-out test set, THIS feature schema) ===")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_, zero_division=0))
    macro_f1 = f1_score(y_test, y_pred, average="macro")
    print(f"Macro-F1 (this schema, held-out test set): {macro_f1:.3f}")
    print("Confusion matrix (rows=true, cols=predicted):")
    print(label_encoder.classes_)
    print(confusion_matrix(y_test, y_pred))

    majority_class = Counter(y_train).most_common(1)[0][0]
    baseline_pred = np.full_like(y_test, majority_class)
    baseline_f1 = f1_score(y_test, baseline_pred, average="macro", zero_division=0)
    print(f"Majority-class baseline macro-F1: {baseline_f1:.3f}")

    # Train the FINAL deployed model on ALL matched data
    # (standard practice: report metrics from the held-out split above,
    # but deploy a model trained on every available real example)
    final_model = xgb.XGBClassifier(**search.best_params_, eval_metric="mlogloss", random_state=42)
    final_model.fit(X, y_enc)

    with open(args.out, "wb") as f:
        pickle.dump({"model": final_model, "encoder": label_encoder}, f)
    print(f"\nSaved production-compatible model (trained on all {len(X)} matched "
          f"incidents) to {args.out}")
    print(f"Classes the model can predict: {list(label_encoder.classes_)}")
    print("\nIMPORTANT: this model can only predict classes it saw real "
          "training data for (above). Any attack class not listed here "
          "(e.g. privilege_escalation, lateral_movement) will NEVER be "
          "predicted by this model, even if a correlation rule fires for "
          "it, until real labeled data for that class is collected and "
          "this script is re-run.")


if __name__ == "__main__":
    main()