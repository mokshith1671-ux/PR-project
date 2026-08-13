import os
import sys
import shutil
import subprocess
import time
import json
from train_model import predict_apk_behavior
from payload_extractor import extract_apk_payloads

# ---------- CONFIG ---------- #

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

INPUT_DIR = os.path.join(BASE_DIR, "input")
OUTPUT_DIR = os.path.join(BASE_DIR, "dataset")
TEMP_EXTRACT_DIR = os.path.join(BASE_DIR, "temp_payloads")
FRIDA_SCRIPT = os.path.join(BASE_DIR, "script.js")

# Create required output folders
BENIGN_OUT = os.path.join(OUTPUT_DIR, "benign")
MALWARE_OUT = os.path.join(OUTPUT_DIR, "malware")
os.makedirs(BENIGN_OUT, exist_ok=True)
os.makedirs(MALWARE_OUT, exist_ok=True)
os.makedirs(TEMP_EXTRACT_DIR, exist_ok=True)


# ---------- PATH RESOLUTION ---------- #

def get_python_cmd():
    venv_py = os.path.join(BASE_DIR, ".venv", "Scripts", "python.exe")
    if os.path.exists(venv_py):
        return f'"{venv_py}"'
    return f'"{sys.executable}"'


def get_frida_cmd():
    venv_frida = os.path.join(BASE_DIR, ".venv", "Scripts", "frida.exe")
    if os.path.exists(venv_frida):
        return f'"{venv_frida}"'
    return "frida"


# ---------- HELPERS ---------- #

def get_package(apk):
    try:
        out = subprocess.check_output(
            f'aapt dump badging "{apk}"',
            shell=True,
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore")

        for line in out.split("\n"):
            if "package: name=" in line:
                return line.split("'")[1]

    except Exception:
        return None


def install_apk(apk):
    subprocess.run(
        f'adb install -r "{apk}"',
        shell=True
    )


def uninstall_apk(pkg):
    subprocess.run(
        f'adb uninstall {pkg}',
        shell=True
    )


# ---------- CORE PIPELINE ---------- #

def process_apk(apk_path, original_source=None, forced_label=None):
    source_info = f" (Origin: {os.path.basename(original_source)})" if original_source else ""
    print(f"\n[+] Processing APK Payload: {apk_path}{source_info}")

    pkg = get_package(apk_path)

    if not pkg:
        print("[!] Could not extract package name via aapt. Skipping.")
        return

    print(f"[*] Package: {pkg}")
    install_apk(apk_path)

    # ---------- START FRIDA ---------- #
    frida_bin = get_frida_cmd()
    proc = subprocess.Popen(
        f'{frida_bin} -U -f {pkg} -l "{FRIDA_SCRIPT}" > output.txt',
        shell=True
    )

    # ---------- INTERACT WITH APP ---------- #
    time.sleep(5)

    subprocess.run(
        f'adb shell monkey -p {pkg} -v 100',
        shell=True
    )

    time.sleep(25)

    # ---------- STOP FRIDA ---------- #
    proc.terminate()

    # ---------- PARSE EVENTS ---------- #
    py_bin = get_python_cmd()
    subprocess.run(
        f'{py_bin} parser.py',
        shell=True
    )

    if not os.path.exists("output.json"):
        print("[!] output.json not generated. Cleaning up.")
        uninstall_apk(pkg)
        return

    with open("output.json", "r", encoding="utf-8", errors="ignore") as f:
        try:
            data = json.load(f)
        except Exception:
            data = None

    if not isinstance(data, list):
        print("[!] Invalid or empty JSON format. Skipping.")
        uninstall_apk(pkg)
        return

    event_count = len(data)
    print(f"[*] Events captured: {event_count}")

    if event_count < 5:
        print("[!] Too few events (< 5) -- skipping.")
        if os.path.exists("output.json"):
            os.remove("output.json")
        uninstall_apk(pkg)
        return

    # ---------- CLASSIFICATION ---------- #
    if forced_label:
        # User explicitly told us this is benign or malware via subfolder placement
        predicted_label = forced_label
        confidence = 1.0
        reason = f"User-labeled ({forced_label})"
        print(f"[LABEL] Forced Class: {predicted_label.upper()} | Source: {reason}")
    else:
        # Use ML model to decide
        predicted_label, confidence, reason = predict_apk_behavior("output.json")
        print(f"[ML] Predicted Class: {predicted_label.upper()} (Confidence: {confidence * 100:.1f}%) | Signals: {reason}")

    # ---------- SAVE AUTOMATICALLY ---------- #
    raw_filename = os.path.basename(apk_path)
    base_name = os.path.splitext(raw_filename)[0]
    out_filename = f"{predicted_label}_{base_name}.json"

    target_folder = MALWARE_OUT if predicted_label == "malware" else BENIGN_OUT
    output_path = os.path.join(target_folder, out_filename)

    if os.path.exists(output_path):
        os.remove(output_path)

    os.replace("output.json", output_path)

    # Cleanup transient txt
    if os.path.exists("output.txt"):
        try:
            os.remove("output.txt")
        except Exception:
            pass

    uninstall_apk(pkg)
    time.sleep(2)

    print(f"[OK] Saved JSON trace to: {output_path}")


# ---------- MAIN ---------- #

def run_all():
    if not os.path.exists(INPUT_DIR):
        print("[!] Input folder not found.")
        return

    print("==================================================")
    print("      AUTOMATED REALTIME MALWARE ANALYSIS PIPELINE")
    print("==================================================")
    print(f"[*] Scanning input files (PDF, Images, ZIPs, APKs) in: {INPUT_DIR}")
    print(f"[*] Outputs will automatically route to:")
    print(f"    - Benign : {BENIGN_OUT}")
    print(f"    - Malware: {MALWARE_OUT}\n")

    # Build list of (file_path, forced_label)
    # input/benign/  -> forced benign
    # input/malware/ -> forced malware
    # input/         -> let ML model decide
    input_benign_dir  = os.path.join(INPUT_DIR, "benign")
    input_malware_dir = os.path.join(INPUT_DIR, "malware")

    input_files = []  # list of (path, forced_label or None)
    for root, dirs, files in os.walk(INPUT_DIR):
        # Skip nested subfolders of benign/malware
        rel = os.path.relpath(root, INPUT_DIR)
        for file in files:
            fpath = os.path.join(root, file)
            if root == input_benign_dir or root.startswith(input_benign_dir + os.sep):
                input_files.append((fpath, "benign"))
            elif root == input_malware_dir or root.startswith(input_malware_dir + os.sep):
                input_files.append((fpath, "malware"))
            else:
                input_files.append((fpath, None))  # ML decides

    if not input_files:
        print("[!] No files found in input folder.")
        return

    print(f"[*] Found {len(input_files)} file(s) in input folder to scan for APK payloads.")
    print(f"[*] Tip: Place files in input/benign/ or input/malware/ to force-label them.\n")

    total_payloads_processed = 0

    for idx, (input_path, forced_label) in enumerate(input_files, 1):
        label_hint = f" [Forced: {forced_label.upper()}]" if forced_label else " [ML will classify]"
        print(f"--- [{idx}/{len(input_files)}] Scanning: {os.path.basename(input_path)}{label_hint} ---")

        # Extract all APK payloads (raw APK, archive, PDF attachment, polyglot byte carving)
        extracted_apks = extract_apk_payloads(input_path, TEMP_EXTRACT_DIR)

        if not extracted_apks:
            print(f"[!] No APK payload found inside: {os.path.basename(input_path)}")
            continue

        print(f"[+] Found {len(extracted_apks)} APK payload(s) inside {os.path.basename(input_path)}")

        for apk_payload in extracted_apks:
            process_apk(apk_payload, original_source=input_path, forced_label=forced_label)
            total_payloads_processed += 1
            # Cleanup extracted temp apk
            if os.path.exists(apk_payload):
                try:
                    os.remove(apk_payload)
                except Exception:
                    pass

    # Cleanup temp directory
    if os.path.exists(TEMP_EXTRACT_DIR):
        try:
            shutil.rmtree(TEMP_EXTRACT_DIR)
        except Exception:
            pass

    print(f"\n[OK] Pipeline Execution Complete! Processed {total_payloads_processed} APK payload(s).")


if __name__ == "__main__":
    run_all()
