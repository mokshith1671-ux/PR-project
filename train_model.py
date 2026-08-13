import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from feature_engineering import extract_features_from_json, FEATURE_COLUMNS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_CSV = os.path.join(BASE_DIR, "features", "dataset_E_top300_balanced.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "malware_detector.pkl")

def train_and_save_model():
    if not os.path.exists(DATASET_CSV):
        print(f"[!] Dataset CSV not found at {DATASET_CSV}, skipping training.")
        return None

    print(f"[*] Training ML model on {DATASET_CSV}...")
    df = pd.read_csv(DATASET_CSV)

    if 'label' not in df.columns:
        print("[!] 'label' column missing from dataset CSV.")
        return None

    X = df[FEATURE_COLUMNS].fillna(0)
    y = df['label'].astype(int)

    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        random_state=42,
        class_weight='balanced'
    )
    rf_model.fit(X, y)

    os.makedirs(MODEL_DIR, exist_ok=True)
    model_data = {
        'model': rf_model,
        'feature_columns': FEATURE_COLUMNS
    }
    joblib.dump(model_data, MODEL_PATH)
    print(f"[OK] Model successfully trained and saved to {MODEL_PATH}")
    return model_data

def get_model():
    if os.path.exists(MODEL_PATH):
        try:
            return joblib.load(MODEL_PATH)
        except Exception as e:
            print(f"[!] Error loading model artifact: {e}")

    return train_and_save_model()

def predict_apk_behavior(json_input):
    """
    Extracts features from JSON trace and predicts whether it is 'malware' or 'benign'.
    Returns:
        label (str): 'malware' or 'benign'
        confidence (float): confidence score between 0.0 and 1.0
        reason (str): brief explanation of prediction
    """
    df_feat = extract_features_from_json(json_input)
    model_data = get_model()

    if model_data and 'model' in model_data:
        model = model_data['model']
        cols = model_data.get('feature_columns', FEATURE_COLUMNS)
        X = df_feat[cols].fillna(0)

        probs = model.predict_proba(X)[0] # [p_benign, p_malware]
        pred_class = int(np.argmax(probs))
        confidence = float(probs[pred_class])

        label = "malware" if pred_class == 1 else "benign"

        # Key risk factors
        high_sig = float(df_feat['high_signal_ratio'].iloc[0])
        crypto_net = float(df_feat['crypto_and_network'].iloc[0])
        dev_net = float(df_feat['device_id_and_network'].iloc[0])
        exec_flag = float(df_feat['has_runtime_exec'].iloc[0])
        dex_flag = float(df_feat['has_dex_load'].iloc[0])

        reasons = []
        if exec_flag > 0: reasons.append("RuntimeExec")
        if dex_flag > 0: reasons.append("DexLoad")
        if crypto_net > 0: reasons.append("Crypto+Network")
        if dev_net > 0: reasons.append("DeviceID+Network")
        if not reasons: reasons.append("Behavioral Features")

        reason_str = f"ML Model ({', '.join(reasons)})"
        return label, confidence, reason_str

    # Fallback to rule-based evaluation if model file cannot be loaded
    print("[!] Using rule-based fallback for property analysis.")
    high_sig = float(df_feat['high_signal_ratio'].iloc[0])
    crypto_net = float(df_feat['crypto_and_network'].iloc[0])
    dev_net = float(df_feat['device_id_and_network'].iloc[0])
    exec_flag = float(df_feat['has_runtime_exec'].iloc[0])
    dex_flag = float(df_feat['has_dex_load'].iloc[0])
    dev_flag = float(df_feat['has_device_id'].iloc[0])

    risk_score = (exec_flag * 0.3) + (dex_flag * 0.3) + (crypto_net * 0.2) + (dev_net * 0.2) + (dev_flag * 0.1) + min(0.3, high_sig * 2)

    if risk_score >= 0.35:
        return "malware", min(0.99, 0.5 + risk_score * 0.5), f"Rule Engine (Risk Score: {risk_score:.2f})"
    else:
        return "benign", min(0.99, 1.0 - risk_score), f"Rule Engine (Low Risk Score: {risk_score:.2f})"

if __name__ == "__main__":
    train_and_save_model()

