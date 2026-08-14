"""
quality_filter.py — Local Stage 2 Pipeline
===========================================
Scans dataset/benign/ and dataset/malware/ for JSON traces,
extracts features, computes quality scores, and MERGES them
with your baseline historical dataset (features/features_raw.csv and
features/dataset_E_top300_balanced.csv).

Preserves the existing 600 baseline samples while adding new APK runs.

Run:
    .venv\Scripts\python.exe quality_filter.py
"""

import os
import json
import math
import hashlib
import pandas as pd
import numpy as np
from pathlib import Path
from feature_engineering import extract_features_from_json, FEATURE_COLUMNS

# ---------- CONFIG ---------- #
BASE_DIR     = Path(__file__).resolve().parent
DATASET_DIR  = BASE_DIR / "dataset"
FEATURES_DIR = BASE_DIR / "features"
FEATURES_DIR.mkdir(exist_ok=True)

RAW_CSV      = FEATURES_DIR / "features_raw.csv"
BALANCED_CSV = FEATURES_DIR / "dataset_E_top300_balanced.csv"
TOP_N        = 300                  # top samples to keep per class

# ---------- MODE ---------- #
# FRESH_START = True  → Ignore existing baseline CSV, train ONLY on your new APKs
# FRESH_START = False → Merge new APKs with existing baseline 600 samples
FRESH_START = True

# Importance weights for quality scoring
WEIGHTS = {
    'runtime_exec': 5.0, 'runtime': 5.0,
    'dex_load': 4.5,
    'sms': 4.5,
    'socket': 4.0,
    'crypto': 3.5,
    'device': 3.5, 'device_id': 3.5,
    'network': 2.5, 'url': 2.5, 'okhttp': 2.5,
    'activity': 1.0,
    'file': 0.5, 'sp': 0.5,
}


def load_events(json_path):
    try:
        with open(json_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def calc_entropy(items):
    if not items:
        return 0.0
    counts = {}
    for x in items:
        counts[x] = counts.get(x, 0) + 1
    total = len(items)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def compute_quality_score(events, feat_row):
    """
    Returns (quality_score, reason_tag) for a trace.
    quality_score is in [0, 1].
    """
    n = len(events)

    if n == 0:
        return 0.0, "dead"

    type_list  = [str(e.get('type', 'unknown')).lower() for e in events if isinstance(e, dict)]
    unique_types = set(type_list)

    volume_score = min(1.0, math.log1p(n) / math.log1p(500))
    diversity_score = min(1.0, len(unique_types) / 10.0)

    weighted_sum = sum(WEIGHTS.get(t, 0.1) for t in type_list)
    importance_score = min(1.0, weighted_sum / 100.0)

    entropy = calc_entropy(type_list)
    max_entropy = math.log2(max(1, len(unique_types)))
    entropy_score = (entropy / max_entropy) if max_entropy > 0 else 0.0

    unique_urls = float(feat_row.get('unique_urls', 0))
    network_score = min(1.0, unique_urls / 10.0)

    high_signal_ratio = float(feat_row.get('high_signal_ratio', 0))
    signal_bonus = min(1.0, high_signal_ratio * 2.0)

    base_score = (
        volume_score    * 0.20 +
        diversity_score * 0.20 +
        importance_score * 0.20 +
        entropy_score   * 0.15 +
        network_score   * 0.10 +
        signal_bonus    * 0.15
    )

    penalty = 1.0
    reason  = "ok"

    if n < 3:
        penalty = 0.05
        reason  = "dead"
    elif n < 10 and len(unique_types) <= 2:
        penalty = 0.20
        reason  = "startup_only"
    elif n < 15:
        penalty = 0.50
        reason  = "sparse"

    return round(base_score * penalty, 6), reason


def minhash_signature(type_list, num_perm=64):
    sig = []
    for i in range(num_perm):
        h = min(
            int(hashlib.md5(f"{i}:{t}".encode()).hexdigest(), 16)
            for t in (type_list or ['__empty__'])
        )
        sig.append(h)
    return sig


def jaccard_from_sigs(sig_a, sig_b):
    return sum(1 for a, b in zip(sig_a, sig_b) if a == b) / len(sig_a)


def apply_duplicate_penalty(df_class, threshold=0.85, penalty=0.30):
    if '_sig' not in df_class.columns:
        return df_class

    sigs = df_class['_sig'].tolist()
    n    = len(sigs)
    penalized = set()

    for i in range(n):
        if i in penalized or not isinstance(sigs[i], list):
            continue
        for j in range(i + 1, n):
            if j in penalized or not isinstance(sigs[j], list):
                continue
            if jaccard_from_sigs(sigs[i], sigs[j]) >= threshold:
                penalized.add(j)

    df_class = df_class.copy()
    idx_list = df_class.index.tolist()
    for pos in penalized:
        idx = idx_list[pos]
        df_class.at[idx, 'quality_score'] *= penalty
        df_class.at[idx, 'quality_reason'] = 'near_duplicate'

    return df_class


def build_dataset():
    print("=" * 60)
    print("  STAGE 2: Quality Scoring & Feature Engineering")
    print("=" * 60)

    # 1. Load existing baseline dataset (only if NOT in fresh-start mode)
    existing_balanced_df = None
    if not FRESH_START and BALANCED_CSV.exists():
        try:
            existing_balanced_df = pd.read_csv(BALANCED_CSV)
            print(f"[*] Loaded baseline balanced dataset: {len(existing_balanced_df)} samples ({BALANCED_CSV.name})")
        except Exception as e:
            print(f"[!] Warning reading existing balanced CSV: {e}")
    elif FRESH_START:
        print("[*] FRESH START mode: Ignoring baseline dataset. Training only on your new APKs.")

    # 2. Extract features for new JSON files in dataset/
    new_rows = []
    for label_name, label_val in [("benign", 0), ("malware", 1)]:
        src_dir = DATASET_DIR / label_name
        if not src_dir.exists():
            continue

        json_files = sorted(src_dir.glob("*.json"))
        if json_files:
            print(f"[*] {label_name.upper()}: Found {len(json_files)} local JSON trace(s).")

        for jf in json_files:
            events   = load_events(jf)
            feat_df  = extract_features_from_json(events)
            feat_row = feat_df.iloc[0].to_dict()

            q_score, q_reason = compute_quality_score(events, feat_row)
            type_list = [str(e.get('type','unknown')).lower() for e in events if isinstance(e, dict)]
            sig = minhash_signature(type_list)

            row = {
                'source_file':   jf.name,
                'label':         label_val,
                'quality_score': q_score,
                'quality_reason': q_reason,
                '_sig':          sig,
            }
            row.update(feat_row)
            new_rows.append(row)

    # 3. Combine existing dataset with newly extracted JSON trace features
    combined_df = None

    if new_rows:
        new_df = pd.DataFrame(new_rows)
        print(f"\n[*] Extracted features for {len(new_df)} new JSON trace(s).")

        # Apply duplicate penalties to new traces
        parts = []
        for lv in [0, 1]:
            subset = new_df[new_df['label'] == lv].copy()
            if len(subset) > 1:
                subset = subset.reset_index(drop=True)
                subset = apply_duplicate_penalty(subset)
            parts.append(subset)
        new_df = pd.concat(parts, ignore_index=True)

        if existing_balanced_df is not None and not FRESH_START:
            # Merge existing baseline rows with new trace rows
            if 'source_file' not in existing_balanced_df.columns:
                existing_balanced_df['source_file'] = [f"baseline_{i}.json" for i in range(len(existing_balanced_df))]
            if 'quality_score' not in existing_balanced_df.columns:
                existing_balanced_df['quality_score'] = 1.0
            if 'quality_reason' not in existing_balanced_df.columns:
                existing_balanced_df['quality_reason'] = 'ok'

            # Avoid duplicates if source_file already in baseline
            existing_sources = set(existing_balanced_df['source_file'].astype(str))
            new_filtered = new_df[~new_df['source_file'].isin(existing_sources)].copy()

            combined_df = pd.concat([existing_balanced_df, new_filtered], ignore_index=True)
            print(f"[+] Merged {len(new_filtered)} new trace(s) into baseline {len(existing_balanced_df)} dataset.")
        else:
            # FRESH_START mode — use only new APKs
            combined_df = new_df
            print(f"[+] Fresh start: using {len(new_df)} newly processed traces only.")
    else:
        print("\n[*] No new JSON traces found in dataset/. Keeping baseline dataset intact.")
        if existing_balanced_df is not None:
            combined_df = existing_balanced_df
        else:
            print("[!] No baseline CSV and no JSON files found. Run Stage 1 first!")
            return

    # Ensure all feature columns exist
    for col in FEATURE_COLUMNS:
        if col not in combined_df.columns:
            combined_df[col] = 0.0

    # Ensure label column exists and is int
    combined_df['label'] = combined_df['label'].astype(int)

    # 4. Save final balanced CSV
    # Ensure balance: select top samples or keep all if balanced
    df_valid = combined_df[combined_df.get('quality_reason', 'ok') != 'dead'].copy()

    benign_df  = df_valid[df_valid['label'] == 0]
    malware_df = df_valid[df_valid['label'] == 1]

    n_b = len(benign_df)
    n_m = len(malware_df)

    # If quality_score present, sort by quality_score, otherwise keep order
    if 'quality_score' in df_valid.columns:
        top_b = benign_df.nlargest(max(TOP_N, n_b), 'quality_score') if n_b > 0 else benign_df
        top_m = malware_df.nlargest(max(TOP_N, n_m), 'quality_score') if n_m > 0 else malware_df
    else:
        top_b = benign_df
        top_m = malware_df

    df_final = pd.concat([top_b, top_m], ignore_index=True)

    # Ensure standard column order for training
    save_cols = [c for c in FEATURE_COLUMNS if c in df_final.columns] + ['label']
    extra_cols = [c for c in ['source_file', 'quality_score', 'quality_reason'] if c in df_final.columns]
    full_save_cols = save_cols + extra_cols

    df_final[full_save_cols].to_csv(BALANCED_CSV, index=False)
    print(f"[OK] {BALANCED_CSV.name} updated: {len(top_b)} benign + {len(top_m)} malware = {len(df_final)} total samples.")

    print()
    print("=" * 60)
    print("  Stage 2 Complete!")
    print("=" * 60)
    print(f"  Total combined samples : {len(df_final)}")
    print(f"  Benign samples         : {len(top_b)}")
    print(f"  Malware samples        : {len(top_m)}")
    print()
    print("  Next step — Run Stage 3:")
    print("  .venv\\Scripts\\python.exe train_model.py")
    print("=" * 60)


if __name__ == "__main__":
    build_dataset()
