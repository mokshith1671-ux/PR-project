import os
import io
import re
import zipfile
import shutil

def is_apk_zip(zip_obj_or_bytes):
    """
    Checks if a zip object or bytes buffer represents a valid Android APK
    by checking for AndroidManifest.xml or classes.dex.
    """
    try:
        if isinstance(zip_obj_or_bytes, bytes):
            z = zipfile.ZipFile(io.BytesIO(zip_obj_or_bytes))
        else:
            z = zip_obj_or_bytes

        namelist = [n.lower() for n in z.namelist()]
        return any('androidmanifest.xml' in name or 'classes.dex' in name for name in namelist)
    except Exception:
        return False


def extract_apk_payloads(file_path, output_dir):
    """
    Scans any input file (raw APK, archive, PDF, image, document, etc.)
    and extracts all embedded APK payloads into output_dir.
    
    Returns:
        extracted_apks (list): list of file paths to extracted APKs.
    """
    os.makedirs(output_dir, exist_ok=True)
    extracted_apks = []

    if not os.path.exists(file_path):
        return extracted_apks

    filename = os.path.basename(file_path)
    base_name = os.path.splitext(filename)[0]

    # 1. Direct APK Check
    try:
        with zipfile.ZipFile(file_path, 'r') as z:
            if is_apk_zip(z):
                # Copy directly to output_dir
                target_path = os.path.join(output_dir, f"{base_name}.apk")
                if os.path.abspath(file_path) != os.path.abspath(target_path):
                    shutil.copy2(file_path, target_path)
                return [target_path]
            else:
                # 2. Archive Container Unpacking (.zip, .jar, etc.)
                for name in z.namelist():
                    if name.lower().endswith('.apk'):
                        extracted_name = f"{base_name}_{os.path.basename(name)}"
                        target_path = os.path.join(output_dir, extracted_name)
                        with z.open(name) as src, open(target_path, 'wb') as dst:
                            shutil.copyfileobj(src, dst)
                        if target_path not in extracted_apks:
                            extracted_apks.append(target_path)
    except Exception:
        pass

    if extracted_apks:
        return extracted_apks

    # 3. Binary Byte Carving (Polyglots, Steganography in PDF, PNG, JPG, XLS, etc.)
    try:
        with open(file_path, 'rb') as f:
            content = f.read()

        # Find all PK\x03\x04 zip headers
        zip_offsets = [m.start() for m in re.finditer(b'PK\x03\x04', content)]
        
        carve_idx = 1
        for offset in zip_offsets:
            sub = content[offset:]
            if len(sub) < 100:
                continue

            try:
                z_buf = io.BytesIO(sub)
                with zipfile.ZipFile(z_buf, 'r') as z:
                    if is_apk_zip(z):
                        carved_filename = f"{base_name}_embedded_{carve_idx}.apk"
                        target_path = os.path.join(output_dir, carved_filename)
                        
                        # Find end of zip structure if possible, or dump buffer
                        with open(target_path, 'wb') as dst:
                            dst.write(sub)
                        
                        extracted_apks.append(target_path)
                        carve_idx += 1
            except Exception:
                continue

    except Exception as e:
        print(f"[!] Error scanning {file_path}: {e}")

    return extracted_apks


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
        out_dir = "temp_extracted"
        res = extract_apk_payloads(test_file, out_dir)
        print(f"[*] Extracted APKs from {test_file}: {res}")
