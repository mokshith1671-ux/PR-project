# Android Dynamic Malware Analysis Framework
### Frida · Android Emulator · Behavioral ML Classification

> End-to-end pipeline: APK → Emulator → Frida hooks → Behavioral JSON → Feature Engineering → ML classifier (~96% accuracy)

---

## Table of Contents

1. Project Overview
2. System Requirements
3. Environment Setup
4. Emulator Configuration
5. Frida Server Setup
6. Project Structure
7. Running the Dynamic Analysis Pipeline
8. Running the ML Notebook
9. Dataset Information
10. Known Issues & Fixes
11. What to Work on Next

---

## 1. Project Overview

This framework executes Android APKs inside an emulator, injects Frida JavaScript hooks into the running process, and captures behavioral events (network calls, file access, crypto usage, runtime execution, DEX loading, SMS, device ID access) into structured JSON traces. Those traces are then scored for quality, filtered, and used to train ML classifiers.

**Pipeline at a glance:**

```
APKs (malware + benign)
        ↓
Android Emulator (API 30, x86_64)
        ↓
Frida Hooks → Runtime Events captured
        ↓
JSON behavioral traces saved per APK
        ↓
Quality filtering (score + rank all traces, keep top-300 per class)
        ↓
Feature engineering → CSV dataset
        ↓
ML training (RF, XGBoost, LightGBM, CatBoost, Ensembles)
        ↓
~96% accuracy on Dataset E (600 quality-filtered samples)
```

**Key files:**

| File | Role |
|---|---|
| `script.js` | Frida JavaScript hooks injected into APK processes |
| `runner.py` | Orchestrates APK install → Frida inject → Monkey events → JSON output → uninstall |
| `parser.py` | Normalizes raw Frida log output into clean JSON |
| `quality_filter.py` | Scores and ranks all JSON traces, outputs top-300 per class |
| `feature_engineering.py` | Converts JSON traces into ML-ready feature vectors |
| `finalBTPcode_final.ipynb` | Full ML training, tuning, ensemble, and evaluation notebook |

---

## 2. System Requirements

| Component | Requirement |
|---|---|
| OS | Windows 10/11 64-bit |
| RAM | 16 GB recommended (8 GB minimum — emulator is heavy) |
| CPU | Must support hardware virtualization (VT-x / AMD-V) — enable in BIOS |
| Disk | 50+ GB free, SSD preferred |
| Python | 3.10 or higher |
| Java | JDK 17 or higher |

> Check BIOS virtualization is on before anything else. Without it, the x86_64 emulator won't run at usable speed.

---

## 3. Environment Setup

### 3.1 Java JDK

Download and install Eclipse Temurin JDK 17 from adoptium.net.

Set environment variable:

```
JAVA_HOME = C:\Program Files\Eclipse Adoptium\jdk-17.x.x.x-hotspot
```

Add to PATH:

```
%JAVA_HOME%\bin
```

Verify:

```bash
java -version
```

---

### 3.2 Android Studio

Download from developer.android.com/studio. During installation ensure these are checked:

- Android SDK
- Android SDK Platform-Tools
- Android Emulator
- Android Virtual Device

After install, open SDK Manager and install **Android 11 (API 30)** under SDK Platforms.

Add these to system PATH:

```
C:\Users\<YourUsername>\AppData\Local\Android\Sdk\platform-tools
C:\Users\<YourUsername>\AppData\Local\Android\Sdk\build-tools\<latest-version>
```

---

### 3.3 Python Packages

```bash
pip install frida-tools
pip install xgboost lightgbm catboost imbalanced-learn datasketch
pip install pandas numpy scikit-learn matplotlib seaborn
```

---

### 3.4 Verify Everything

Run all three — all must succeed before proceeding:

```bash
adb version
aapt version
frida --version
```

Note the exact `frida --version` output — you need this number in the next step.

---

## 4. Emulator Configuration

### 4.1 Create Virtual Device

1. Android Studio → Tools → Device Manager → Create Device
2. Select hardware: **Pixel 5**
3. System image: **API 30, x86_64, Google APIs**
4. Download the image if prompted

Settings to configure:

| Setting | Value |
|---|---|
| RAM | 4096 MB (minimum 2048) |
| VM Heap | 512 MB |
| Internal Storage | 6 GB |
| SD Card | 512 MB |
| Graphics | Hardware — GLES 2.0 |

> Must be x86_64. Do NOT use an ARM image — the Frida server binary won't match and it runs too slowly for batch processing anyway.

### 4.2 Start Emulator

```bash
adb devices
```

Expected:

```
emulator-5554   device
```

Wait for full boot to home screen before running anything.

---

## 5. Frida Server Setup

This must be done every time after an emulator restart.

### 5.1 Download Frida Server

Go to: github.com/frida/frida/releases

Download the file matching your `frida --version` exactly:

```
frida-server-<YOUR-VERSION>-android-x86_64.xz
```

Extract with 7-Zip. Rename the extracted file to `frida-server`.

### 5.2 Push to Emulator

```bash
adb push frida-server /data/local/tmp/
```

### 5.3 Start Frida Server

```bash
adb shell
su
chmod 755 /data/local/tmp/frida-server
/data/local/tmp/frida-server &
exit
```

### 5.4 Verify Connection

```bash
frida-ps -U
```

You should see a list of running emulator processes. If you do, Frida is working.

> "Address already in use" = server already running, safe to ignore.
> Empty output or error = version mismatch or emulator not fully booted. Restart emulator, repeat.

---

## 6. Project Structure

```
project/
│
├── input/
│    ├── malware/          ← place malware APKs here
│    └── benign/           ← place benign APKs here
│
├── dataset/               ← generated JSON behavioral traces
│    ├── malware/
│    └── benign/
│
├── filtered/              ← quality-filtered Dataset E traces
│    ├── top300_malware/
│    └── top300_benign/
│
├── features/
│    ├── features_raw.csv                  ← features from all 1044 samples
│    └── dataset_E_top300_balanced.csv     ← features from Dataset E (600 samples)
│
├── models/
│    └── malware_detector.pkl              ← saved best model
│
├── script.js                  ← Frida hooks
├── runner.py                  ← main dynamic analysis pipeline
├── parser.py                  ← log parser
├── quality_filter.py          ← behavioral quality scoring
├── feature_engineering.py     ← JSON → feature CSV
└── finalBTPcode_final.ipynb   ← ML notebook
```

---

## 7. Running the Dynamic Analysis Pipeline

### Step 1 — Place APKs

```
input/malware/   ← malware APKs
input/benign/    ← benign APKs
```

### Step 2 — Confirm emulator is running

```bash
adb devices
```

### Step 3 — Confirm Frida server is running

```bash
frida-ps -U
```

If not running, repeat Section 5.3.

### Step 4 — Run the pipeline

```bash
cd path/to/project
python -u runner.py
```

For each APK, runner.py will:
1. Extract package name via `aapt`
2. Install APK via `adb install`
3. Spawn process via Frida
4. Inject `script.js` hooks before any app code runs
5. Resume the process
6. Trigger UI interaction via `adb shell monkey`
7. Collect behavioral events for the configured time window
8. Write JSON trace to `dataset/malware/` or `dataset/benign/`
9. Uninstall the APK
10. Move to next APK

> Process in batches of 20–30 APKs at a time. Restart the emulator between batches — memory accumulates and slows things down significantly.

### Step 5 — (Optional) Run quality filtering

```bash
python quality_filter.py
```

Scores all JSON traces across 5 dimensions (event volume, behavioral diversity, entropy, weighted malware indicators, duplicate detection via MinHash LSH). Keeps top-300 per class. Writes to `filtered/`.

### Step 6 — Feature engineering

```bash
python feature_engineering.py
```

Reads JSONs, outputs feature CSV to `features/`.

---

## 8. Running the ML Notebook

The notebook (`finalBTPcode_final.ipynb`) is designed for Google Colab but also runs locally.

### Option A — Google Colab

1. Upload notebook to Colab
2. Upload `dataset_E_top300_balanced.csv` to Google Drive at `MyDrive/recent-dataset/`
3. Run Cell 1 (installs all packages automatically)
4. Mount Drive when prompted
5. Run all cells in order

### Option B — Local Jupyter

```bash
pip install jupyter
jupyter notebook finalBTPcode_final.ipynb
```

Place `dataset_E_top300_balanced.csv` in the same folder as the notebook. If it's elsewhere, update `SEARCH_PATHS` in Cell 1.

### Notebook execution order

| Cell | What it does |
|---|---|
| 1 | Installs xgboost, lightgbm, catboost, imbalanced-learn, datasketch |
| 2 | Mounts Google Drive (Colab only) |
| 3 | Loads Dataset E, drops housekeeping columns |
| 4 | Adds interaction features: log-transforms, signal ratios, co-occurrence flags |
| 5 | Train/val split (80/20 stratified) + RobustScaler |
| 6 | Baseline models: RF, XGBoost, LightGBM, KNN, MLP |
| 7 | GridSearchCV tuning for XGBoost, LightGBM, Random Forest |
| 8 | Voting ensemble (RF + XGB + LGB), Stacking ensemble |
| 9 | Grid-search over ensemble weights |
| 10 | CatBoost baseline + tuned CatBoost |
| 11 | RFE feature selection + ensemble on top-20 features |
| 12 | Consolidated results table + bar charts for all models |

### Save best model

```python
import joblib
joblib.dump(best_catb, "models/malware_detector.pkl")

# Load and predict
model = joblib.load("models/malware_detector.pkl")
pred = model.predict(new_features_dataframe)
```

---

## 9. Dataset Information

### Dataset versions

| Version | Samples | Notes |
|---|---|---|
| Raw Phase 1 | ~600 | Initial collection, ~92% accuracy |
| Raw Phase 2 | ~1044 | Expanded, accuracy dropped to ~88–91% due to noisy traces |
| Dataset E | 600 | Quality-filtered: top-300 benign + top-300 malware. ~96% accuracy |

Dataset E is what the notebook uses. It removed:
- 93 dead executions (≤ 2 events)
- 259 near-duplicate traces (MinHash LSH, Jaccard ≥ 0.85)
- 118 startup-only traces
- 136 sparse traces (< 15 events)

### Dataset links (Google Drive)

| Resource | Description |
|---|---|
| Full JSON dataset | All raw behavioral traces |
| Dataset E CSV | `dataset_E_top300_balanced.csv` — ready for notebook |
| ML Notebook | `finalBTPcode_final.ipynb` |
| Dataset restore code | Script to reconstruct dataset from CSV |

> Links: check project summary PDF for current Google Drive URLs.

### Behavioral features extracted per trace

Statistical: `n_events`, `duration_ms`, `event_density`, `ts_entropy`

Counts: `cnt_network`, `cnt_file`, `cnt_runtime_exec`, `cnt_dex_load`, `cnt_crypto`, `cnt_sms`, `cnt_socket`, `cnt_device_id`

Binary flags: `has_crypto`, `has_network`, `has_dex_load`, `has_runtime_exec`, `has_sms`, `has_device_id`, `has_subscriber_id`

Derived/interaction: `high_signal_ratio`, `noise_ratio`, `signal_to_noise`, `crypto_x_network`, `dex_x_exec`, `deviceid_x_network`, `webview_x_url`, `sms_x_deviceid`, `richness_x_volume`

---

## 10. Known Issues & Fixes

| Issue | Cause | Fix |
|---|---|---|
| `adb not recognized` | PATH not set | Add platform-tools to system PATH |
| `aapt not found` | PATH not set | Add build-tools to PATH |
| `frida-ps -U` returns nothing | Version mismatch or server not running | Match frida-tools version exactly; restart server |
| Empty JSON output | APK crashed, Frida inject failed, or dormant malware | Check ADB logcat for crash; increase execution time; these will be filtered by quality scorer |
| `INSTALL_FAILED_ALREADY_EXISTS` | Previous run didn't clean up | Run `adb uninstall <package_name>` manually |
| Emulator freezes mid-batch | Memory accumulation | Restart emulator every 20–30 APKs |
| `Address already in use` on frida-server | Server already running | Not an error — proceed normally |
| APK installs but crashes immediately | ABI mismatch (ARM-only native libs on x86_64) | These produce dead traces, quality filter removes them |
| Notebook: CSV not found | Wrong path | Update `SEARCH_PATHS` list in Cell 1 or upload CSV to same folder |
| CatBoost install fails in Colab | Colab environment | Run `!pip install -q catboost` in a separate cell first |

---

## 11. What to Work on Next

If you're picking this up to extend the research, here's where the biggest gains are:

**Improve behavioral coverage (highest impact)**

Replace `adb shell monkey` with UIAutomator2 or Appium. Monkey generates random touches — it can't navigate login screens, dismiss dialogs, or trigger specific flows. Many APKs require actual user interaction to activate. This is the single biggest gap in the current pipeline.

**Add more APKs (but filter them)**

Don't just dump more APKs in and retrain. Every new APK should go through `quality_filter.py`. The Phase 2 experiment showed that adding noisy samples actively hurts accuracy. Quantity only helps if quality is maintained.

**Handle dormant malware**

Some malware samples wait for C2 commands or SMS triggers before doing anything. To capture these: set up a fake C2 server (something like Wireshark + a simple Python socket server on a routable address inside the emulator network), or use intent fuzzing to simulate external triggers.

**Add network packet capture**

Frida captures URL strings and hostnames. Add `tcpdump` or route emulator traffic through `mitmproxy` to get full packet-level network data — payload sizes, TLS fingerprints, connection patterns. This opens up a richer set of network features.

**Temporal/sequence features**

Current features are bag-of-events (order ignored). Try n-gram TF-IDF over event type sequences. Event ordering carries signal — e.g., `device_id → crypto → network` is a more suspicious pattern than those three events in any random order.

**Anti-emulation hardening**

Some sophisticated samples detect they're in an emulator and go quiet. Research emulator fingerprint spoofing: fake IMEI, realistic sensor values, proper device properties. Tools like `AndroGuard` and `apk-mitm` can help inspect what checks a sample is running.

**Multi-run averaging**

Currently each APK is run once. Run each APK 3 times with different Monkey seeds and merge the behavioral events. This reduces variance from probabilistic UI interaction and produces richer traces.

---

*For theoretical background, dataset quality methodology, and full experimental results — see the detailed project report.*
