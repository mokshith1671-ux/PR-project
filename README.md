# Android Dynamic Malware Analysis & Embedded Payload Framework
### Frida · Android Emulator · Binary Carving · Behavioral ML Classification

> End-to-end 3-Stage Pipeline: Multi-file Input (PDF/PNG/ZIP/APK) → Payload Extraction → Emulator & Frida Dynamic Analysis → Behavioral JSON → Quality Filtering & Merging → ML Classification (~96% accuracy)

---

## Table of Contents

1. [Project Architecture & Pipeline](#1-project-architecture--pipeline)
2. [Key Components](#2-key-components)
3. [Environment & Prerequisites](#3-environment--prerequisites)
4. [Frida & Emulator Setup](#4-frida--emulator-setup)
5. [Project Structure](#5-project-structure)
6. [3-Stage Execution Workflow](#6-3-stage-execution-workflow)
   - [Stage 1: Dynamic Analysis & Payload Extraction](#stage-1-dynamic-analysis--payload-extraction)
   - [Stage 2: Quality Filtering & Dataset Merging](#stage-2-quality-filtering--dataset-merging)
   - [Stage 3: ML Model Training & Inference](#stage-3-ml-model-training--inference)
7. [Running the Jupyter Notebook](#7-running-the-jupyter-notebook)
8. [Dataset Information](#8-dataset-information)
9. [Troubleshooting & FAQs](#9-troubleshooting--faqs)

---

## 1. Project Architecture & Pipeline

Attackers don't always deliver raw `.apk` files. They often embed APK payloads inside benign-looking container files like `.pdf`, `.png`, `.zip`, or hidden file streams. This framework handles both raw `.apk` files and embedded payloads seamlessly.

```
       [ Input Directory: input/ ]
 (PDF, PNG, ZIP, or APK files containing hidden payloads)
                     │
                     ▼
  ┌──────────────────────────────────────────────────┐
  │ STAGE 1: Payload Extraction & Dynamic Analysis   │
  │ • payload_extractor.py: Carves embedded APKs     │
  │ • runner.py: Installs & injects Frida hooks     │
  │ • Monkey UI events → Behavioral JSON traces      │
  │ • Predicts & routes traces to dataset/           │
  └──────────────────────────┬───────────────────────┘
                             │
                             ▼
  ┌──────────────────────────────────────────────────┐
  │ STAGE 2: Quality Filtering & Dataset Merging    │
  │ • quality_filter.py: Scores behavioral quality   │
  │ • Removes dead, duplicate, & sparse traces       │
  │ • Merges new traces with 600 baseline samples    │
  │ • Outputs: dataset_E_top300_balanced.csv         │
  └──────────────────────────┬───────────────────────┘
                             │
                             ▼
  ┌──────────────────────────────────────────────────┐
  │ STAGE 3: Machine Learning Model Training         │
  │ • train_model.py: Trains Random Forest model     │
  │ • finalBTPcode_models.ipynb: Full ML benchmark   │
  │ • Saves deployment model: models/malware_detector.pkl │
  └──────────────────────────────────────────────────┘
```

---

## 2. Key Components

| File | Role |
|---|---|
| `payload_extractor.py` | Scans input files (.pdf, .png, .zip, .apk) and carves hidden APK payloads |
| `script.js` | Frida JavaScript hooks for dynamic API interception (crypto, network, SMS, DEX loading, exec) |
| `runner.py` | Stage 1 orchestrator: Extract → Install → Frida Inject → Monkey Events → Dynamic Route |
| `parser.py` | Parses raw Frida hook output into clean, structured JSON behavioral traces |
| `quality_filter.py` | Stage 2 pipeline: Quality scoring, duplicate detection (MinHash LSH), dataset merging |
| `feature_engineering.py` | Extracts 60+ statistical, count, ratio, and co-occurrence features from JSONs |
| `train_model.py` | Stage 3 ML trainer: Trains model on Dataset E and saves `models/malware_detector.pkl` |
| `finalBTPcode_models.ipynb` | Complete ML experiment notebook (RF, XGBoost, LightGBM, CatBoost, Ensembles) |

---

## 3. Environment & Prerequisites

### System Requirements
- **OS**: Windows 10/11 64-bit
- **RAM**: 16 GB recommended (8 GB minimum)
- **Virtualization**: VT-x / AMD-V enabled in BIOS
- **Python**: 3.10+ (using local `.venv`)
- **Java**: JDK 17 (Eclipse Temurin)

### Setup Commands (Windows PowerShell)

```cmd
# Create virtual environment
python -m venv .venv

# Install required packages
.venv\Scripts\pip.exe install frida-tools datasketch pandas numpy scikit-learn matplotlib seaborn xgboost lightgbm catboost imbalanced-learn
```

---

## 4. Frida & Emulator Setup

1. **Android Emulator**:
   - API 30, x86_64 system image (Google APIs) in Android Studio Device Manager.
   - Start emulator and verify:
     ```cmd
     adb devices
     ```

2. **Frida Server**:
   - Download matching `frida-server` for your `frida --version` from [Frida Releases](https://github.com/frida/frida/releases) (x86_64 architecture).
   - Push and start frida-server on emulator:
     ```cmd
     adb push frida-server /data/local/tmp/
     adb shell "su root chmod 755 /data/local/tmp/frida-server"
     adb shell "su root /data/local/tmp/frida-server &"
     ```
   - Verify connection:
     ```cmd
     frida-ps -U
     ```

---

## 5. Project Structure

```text
final_project/
│
├── input/                                ← Drop target files to analyze (.apk, .pdf, .png, .zip)
│   ├── 8. PWM in STM32.pdf               ← Example PDF with embedded payload
│   ├── com.neumorphic.calculator_2.apk   ← Target APK file
│   └── swati4star.createpdf_110.apk       ← Target APK file
│
├── dataset/                              ← Captured JSON behavioral traces (Stage 1 output)
│   ├── benign/                           ← Benign app trace outputs
│   └── malware/                          ← Malware app trace outputs
│
├── filtered/                             ← Quality-filtered dataset traces
│   ├── quality_scores.csv                ← Quality scores & MinHash LSH penalty metrics
│   ├── top300_benign/                    ← Top 300 benign JSON traces
│   └── top300_malware/                   ← Top 300 malware JSON traces
│
├── features/                             ← Feature matrices ready for Machine Learning
│   ├── features_raw.csv                  ← Feature matrix from raw un-filtered traces
│   └── dataset_E_top300_balanced.csv     ← Curated Dataset E (602 balanced samples)
│
├── models/                               ← Machine Learning models directory
│   └── malware_detector.pkl              ← Serialized Random Forest classifier artifact
│
├── script.js                             ← Frida JavaScript hooks for API interception
├── payload_extractor.py                  ← Stage 1: Carves hidden APK payloads from non-APK files
├── runner.py                             ← Stage 1: ADB & Frida dynamic analysis orchestrator
├── parser.py                             ← Stage 1: Normalizes Frida log outputs into JSON traces
├── quality_filter.py                     ← Stage 2: Quality scoring, duplicate removal, & dataset merger
├── feature_engineering.py                ← Stage 2: Feature matrix extractor (60+ behavioral features)
├── train_model.py                        ← Stage 3: Trains ML model and updates malware_detector.pkl
├── finalBTPcode_models.ipynb             ← Stage 3: Full ML benchmark & experiment notebook
├── BTP_Final_Report_Android_Malware.pdf  ← Project research documentation
├── .gitignore                            ← Git exclusions (.venv, __pycache__, frida-server)
└── README.md                             ← Project documentation & setup instructions
```

---

## 6. 3-Stage Execution Workflow

### Stage 1: Dynamic Analysis & Payload Extraction
Place any target files (`.apk`, `.pdf`, `.png`, `.zip`) into the `input/` folder and execute:

```cmd
.venv\Scripts\python.exe runner.py
```
*Processes all payloads, injects Frida hooks, captures behavioral events, predicts class using existing model, and saves JSON traces to `dataset/`.*

### Stage 2: Quality Filtering & Dataset Merging
Run Stage 2 to score the quality of newly generated JSON traces and merge them into your baseline dataset:

```cmd
.venv\Scripts\python.exe quality_filter.py
```
*Computes quality scores, penalizes duplicate/sparse runs, preserves your 600 historical baseline samples, and updates `features/dataset_E_top300_balanced.csv`.*

### Stage 3: ML Model Training & Inference
Train or retrain your ML classifier on the updated dataset:

```cmd
.venv\Scripts\python.exe train_model.py
```
*Trains a Random Forest classifier on Dataset E and updates `models/malware_detector.pkl` for real-time inference during Stage 1.*

---

## 7. Running the Jupyter Notebook

To run the full benchmark notebook (`finalBTPcode_models.ipynb`):

1. Open the notebook in VS Code or Jupyter.
2. Select kernel: **`Python (.venv)`**.
3. Skip Cell 2 (Google Drive mount — Colab only).
4. Run all remaining cells.

*Note: The notebook automatically locates `features/dataset_E_top300_balanced.csv` and cleans non-numeric metadata before feature scaling.*

---

## 8. Dataset Information

- **Dataset E**: Top 300 Benign + Top 300 Malware baseline traces + newly analyzed APK runs.
- **Extracted Features (70+)**:
  - Event volume & duration (`n_events`, `temporal_span_ms`).
  - Behavioral entropy (`behavioral_entropy`, `temporal_entropy`).
  - API counts & flags (`cnt_runtime_exec`, `cnt_dex_load`, `cnt_crypto`, `cnt_sms`, `cnt_socket`).
  - Co-occurrence flags (`crypto_x_network`, `deviceid_x_network`, `dex_x_exec`, `sms_x_deviceid`).
  - Signal-to-noise ratios (`high_signal_ratio`, `signal_to_noise`).

---

## 9. Troubleshooting & FAQs

- **`ValueError: could not convert string to float: 'ok'`**: Fixed by dropping non-numeric columns (`quality_reason`, `source_file`) when loading `dataset_E_top300_balanced.csv`.
- **`IndexError: index 1 is out of bounds`**: Occurs if dataset has only 1 class. Always use `quality_filter.py` to maintain a balanced dataset with both benign and malware samples.
- **Large push errors on GitHub (`frida-server > 100MB`)**: Added `frida-server*` to `.gitignore`.
