import os
import time
import json
import lzma
from threading import Lock
import httpx

CACHE_DIR = "cache"
CACHE_FILE_COMPRESSED = os.path.join(CACHE_DIR, "CVE-all.json.xz")
CACHE_DURATION = 86400  # 24 hours

cve_data_cache = None  # Shared memory
cache_lock = Lock()

def ensure_cache_dir():
    if not os.path.exists(CACHE_DIR):
        try:
            os.makedirs(CACHE_DIR)
            print(f"[+] Created cache directory at '{CACHE_DIR}'.")
        except Exception as e:
            print(f"[!] Failed to create cache directory '{CACHE_DIR}': {e}")

def is_cache_valid() -> bool:
    if os.path.exists(CACHE_FILE_COMPRESSED):
        cache_mtime = os.path.getmtime(CACHE_FILE_COMPRESSED)
        current_time = time.time()
        return (current_time - cache_mtime) < CACHE_DURATION
    return False

def download_and_cache():
    try:
        print("[*] Downloading NVD CVE JSON feed...")
        response = httpx.get(
            "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-all.json.xz",
            timeout=30,
            follow_redirects=True
        )
        if response.status_code == 200:
            with open(CACHE_FILE_COMPRESSED, "wb") as f:
                f.write(response.content)
            print("[+] Downloaded and cached NVD CVE JSON feed.")
        else:
            print(f"[!] Failed to download NVD CVE feed. Status code: {response.status_code}")
    except Exception as e:
        print(f"[!] Error downloading NVD CVE feed: {e}")

def load_cve_data_into_memory():
    global cve_data_cache
    with cache_lock:
        if cve_data_cache is not None:
            return  # Data already loaded

        ensure_cache_dir()

        if not is_cache_valid():
            download_and_cache()

        try:
            print("[*] Loading NIST CVE data into memory...")
            with lzma.open(CACHE_FILE_COMPRESSED, "rt", encoding="utf-8") as f:
                cve_data_cache = json.load(f)
            print("[+] CVE data loaded into memory successfully.")
        except Exception as e:
            print(f"[!] Error loading NIST data from compressed file: {e}")
            cve_data_cache = {}

def get_cve_data_cache():
    load_cve_data_into_memory()
    return cve_data_cache
