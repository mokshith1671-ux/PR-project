import os
import subprocess
import time
import json

# ---------- CONFIG ---------- #

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

INPUT_DIR = os.path.join(BASE_DIR, "input")
OUTPUT_DIR = os.path.join(BASE_DIR, "dataset")
FRIDA_SCRIPT = os.path.join(BASE_DIR, "script.js")

# Create required folders
os.makedirs(os.path.join(OUTPUT_DIR, "benign"), exist_ok=True)
os.makedirs(os.path.join(OUTPUT_DIR, "malware"), exist_ok=True)


# ---------- HELPERS ---------- #

def get_package(apk):
    try:
        out = subprocess.check_output(
            f'aapt dump badging "{apk}"',
            shell=True,
            stderr=subprocess.DEVNULL
        ).decode()

        for line in out.split("\n"):
            if "package: name=" in line:
                return line.split("'")[1]

    except:
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

def process_apk(apk_path, label):

    print(f"\n📦 Processing: {apk_path}")

    pkg = get_package(apk_path)

    if not pkg:
        print("❌ Package not found")
        return

    install_apk(apk_path)

    # ---------- START FRIDA ---------- #

    proc = subprocess.Popen(
        f'frida -U -f {pkg} -l "{FRIDA_SCRIPT}" > output.txt',
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

    subprocess.run(
        "python parser.py",
        shell=True
    )

    if not os.path.exists("output.json"):
        print("❌ output.json not generated")
        uninstall_apk(pkg)
        return

    with open("output.json", "r") as f:
        data = json.load(f)

    if not isinstance(data, list):
        print("❌ Invalid JSON format")
        uninstall_apk(pkg)
        return

    event_count = len(data)

    print(f"📊 Events captured: {event_count}")

    if event_count == 0:
        print("⚠️ No events — skipping")
        uninstall_apk(pkg)
        return

    if event_count < 5:
        print("⚠️ Too few events — skipping")
        uninstall_apk(pkg)
        return

    # ---------- SAVE ---------- #

    filename = os.path.basename(apk_path).replace(".apk", ".json")

    save_folder = os.path.join(OUTPUT_DIR, label)

    os.makedirs(save_folder, exist_ok=True)

    output_path = os.path.join(
        save_folder,
        f"{label}_{filename}"
    )

    if os.path.exists(output_path):
        os.remove(output_path)

    os.replace("output.json", output_path)

    uninstall_apk(pkg)

    time.sleep(3)

    print(f"✅ Saved: {output_path}")


# ---------- MAIN ---------- #

def run_all():

    if not os.path.exists(INPUT_DIR):
        print("❌ input folder not found")
        return

    for label in os.listdir(INPUT_DIR):

        folder = os.path.join(INPUT_DIR, label)

        if not os.path.isdir(folder):
            continue

        print(f"\n📂 Processing category: {label}")

        for apk in os.listdir(folder):

            if apk.endswith(".apk"):

                apk_path = os.path.join(folder, apk)

                process_apk(apk_path, label)

    print("\n🚀 DONE")


# ---------- ENTRY ---------- #

if __name__ == "__main__":
    run_all()