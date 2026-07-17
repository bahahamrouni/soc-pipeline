#!/usr/bin/env python3
"""
Trains XGBoost on labeled_dataset.csv (from 07_build_labeled_dataset.py) with
a leakage-safe split, and evaluates it properly: per-class precision/recall/
F1, confusion matrix, macro-F1, a majority-class baseline, a rule-only
baseline, and a false-positive rate on the benign holdout.

pip install xgboost scikit-learn pandas --break-system-packages
"""
import pandas as pd
import numpy as np
from sklearn.model_selection import GroupShuffleSplit, StratifiedKFold, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.preprocessing import LabelEncoder
from sklearn.dummy import DummyClassifier
from sklearn.calibration import calibration_curve
import xgboost as xgb

DATA_PATH = "labeled_dataset.csv"

df = pd.read_csv(DATA_PATH)
print(f"Loaded {len(df)} labeled alerts across {df['label'].nunique()} classes:")
print(df["label"].value_counts())

# ---- Feature engineering from Wazuh alert fields (NOT flow features) ----
# Categorical Wazuh fields -> encoded features. Expand this as you add more
# fields to 07_build_labeled_dataset.py (e.g. decoder name, MITRE id).
cat_cols = ["rule_id", "agent_name", "rule_groups"]
for c in cat_cols:
    df[c] = df[c].astype(str).fillna("unknown")
    df[c + "_enc"] = LabelEncoder().fit_transform(df[c])

df["rule_level"] = pd.to_numeric(df["rule_level"], errors="coerce").fillna(0)

feature_cols = [c + "_enc" for c in cat_cols] + ["rule_level"]
X = df[feature_cols].values
y_raw = df["label"].values
groups = df["run_id"].astype(str).values  # group by INDEPENDENT run, not scenario type

label_enc = LabelEncoder()
y = label_enc.fit_transform(y_raw)
class_names = label_enc.classes_

from sklearn.model_selection import train_test_split

def _try_group_split(X, y, groups, class_names):
    """Attempt a leakage-safe group split. Returns None if any class ends
    up missing from train or test (a single-group class, e.g. a benign
    baseline collected as one continuous run, can't be split and may land
    entirely in one bucket by chance)."""
    gss = GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=42)
    train_idx, test_idx = next(gss.split(X, y, groups))
    if len(np.unique(y[train_idx])) < len(class_names) or len(np.unique(y[test_idx])) < len(class_names):
        return None
    groups_train = groups[train_idx]
    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.176, random_state=42)
    tr_idx, val_idx = next(gss2.split(X[train_idx], y[train_idx], groups_train))
    final_train_idx = train_idx[tr_idx]
    val_idx = train_idx[val_idx]
    if len(np.unique(y[final_train_idx])) < len(class_names):
        return None
    return final_train_idx, val_idx, test_idx

result = _try_group_split(X, y, groups, class_names)
n_groups = len(np.unique(groups))

if result is not None:
    train_idx, val_idx, test_idx = result
    X_train, X_val, X_test = X[train_idx], X[val_idx], X[test_idx]
    y_train, y_val, y_test = y[train_idx], y[val_idx], y[test_idx]
    split_method = f"grouped by run_id ({n_groups} independent runs)"
else:
    print(f"\nWARNING: {n_groups} independent runs across {len(class_names)} "
          f"classes was not enough for every class to appear in every split "
          f"bucket (this happens when a class was collected as a single "
          f"continuous run, e.g. one benign baseline window, which cannot "
          f"itself be subdivided into independent groups). Falling back to "
          f"a STRATIFIED PER-ALERT split. LIMITATION for the report: alerts "
          f"from the same run may appear in both train and test for "
          f"under-represented classes, which can inflate their reported "
          f"metrics. Collecting more independent runs (e.g. several shorter "
          f"benign windows instead of one long one) would resolve this.")
    all_idx = np.arange(len(X))
    train_idx, test_idx = train_test_split(
        all_idx, test_size=0.15, random_state=42, stratify=y)
    train_idx, val_idx = train_test_split(
        train_idx, test_size=0.176, random_state=42, stratify=y[train_idx])
    X_train, X_val, X_test = X[train_idx], X[val_idx], X[test_idx]
    y_train, y_val, y_test = y[train_idx], y[val_idx], y[test_idx]
    split_method = "stratified per-alert (grouped split not viable - see warning above)"

print(f"\nSplit method: {split_method}")
print(f"Split sizes -> train: {len(X_train)}, val: {len(X_val)}, test: {len(X_test)}")

# ---- Hyperparameter search via stratified k-fold on TRAIN only ----
param_grid = {
    "max_depth": [4, 6, 8],
    "learning_rate": [0.05, 0.1, 0.2],
    "n_estimators": [100, 200],
}
base_model = xgb.XGBClassifier(eval_metric="mlogloss", random_state=42)
min_class_count = pd.Series(y_train).value_counts().min()
n_splits = max(2, min(5, int(min_class_count)))
if n_splits < 5:
    print(f"NOTE: smallest class in training set has only {min_class_count} "
          f"sample(s) - using {n_splits}-fold CV instead of 5-fold.")
skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
search = GridSearchCV(base_model, param_grid, cv=skf, scoring="f1_macro", n_jobs=-1)
search.fit(X_train, y_train)
model = search.best_estimator_
print(f"\nBest params: {search.best_params_}")

# ---- Evaluate on held-out TEST set (touched once) ----
y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)

print("\n=== Classification report (test set) ===")
all_labels = np.arange(len(class_names))
print(classification_report(y_test, y_pred, labels=all_labels,
                             target_names=class_names, digits=3, zero_division=0))

print("=== Confusion matrix (rows=true, cols=predicted) ===")
cm = confusion_matrix(y_test, y_pred, labels=all_labels)
print(pd.DataFrame(cm, index=class_names, columns=class_names))

macro_f1 = f1_score(y_test, y_pred, labels=all_labels, average="macro")
print(f"\nMacro-F1 (headline metric): {macro_f1:.3f}")
if len(np.unique(y_test)) < len(class_names):
    print("NOTE: not every class appeared in the test split (small group "
          "count for some class) - collect more repetitions per scenario "
          "so every class has enough independent runs to survive the "
          "group-based split.")

# ---- Baseline 1: majority class ----
dummy = DummyClassifier(strategy="most_frequent")
dummy.fit(X_train, y_train)
dummy_pred = dummy.predict(X_test)
print(f"\nMajority-class baseline macro-F1: {f1_score(y_test, dummy_pred, labels=all_labels, average='macro', zero_division=0):.3f}")
print(f"Majority-class baseline accuracy:  {(dummy_pred == y_test).mean():.3f}  "
      f"(compare this to overall accuracy above - if they're close, the model isn't adding much)")

# ---- Baseline 2: rule-level-only (mimics "just use Wazuh's default level") ----
# crude proxy: threshold rule_level as the only signal
level_test = df.iloc[test_idx]["rule_level"].values
# pick whatever threshold best separates classes on train, simple version:
rule_only_pred = np.where(level_test >= 10, 1, 0)  # placeholder binary proxy
print("\n(Rule-only baseline is a simplification here - for the report, "
      "compute precision/recall of CORR-001..005 alone against the same "
      "test set labels for an apples-to-apples comparison.)")

# ---- False positive rate on benign class specifically ----
if "benign" in class_names:
    benign_idx = list(class_names).index("benign")
    benign_mask_true = y_test == benign_idx
    if benign_mask_true.sum() > 0:
        fp_rate = (y_pred[benign_mask_true] != benign_idx).mean()
        print(f"\nFalse positive rate on benign holdout: {fp_rate:.3%} "
              f"({benign_mask_true.sum()} benign alerts tested)")
    else:
        print("\nNo benign samples in test split - run BENIGN-01 with more "
              "volume, or check GroupShuffleSplit didn't put all benign in train.")
else:
    print("\nWARNING: no 'benign' class in labeled_dataset.csv - false "
          "positive rate cannot be computed. Add the benign data collection "
          "run before finalizing evaluation.")

# ---- Calibration check (optional but relevant given dashboard confidence scores) ----
# one-vs-rest for the most common class as an example
top_class_idx = pd.Series(y_test).value_counts().idxmax()
y_test_binary = (y_test == top_class_idx).astype(int)
prob_top = y_proba[:, top_class_idx]
if len(np.unique(y_test_binary)) > 1:
    frac_pos, mean_pred = calibration_curve(y_test_binary, prob_top, n_bins=5)
    print(f"\nCalibration check for class '{class_names[top_class_idx]}' "
          f"(predicted confidence vs actual frequency, should track closely):")
    for mp, fp in zip(mean_pred, frac_pos):
        print(f"  predicted ~{mp:.2f} -> actual {fp:.2f}")

model.save_model("xgboost_model_v2.json")
print("\nSaved model to xgboost_model_v2.json")