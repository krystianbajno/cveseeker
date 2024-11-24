import os
import time
import json
import lzma
import httpx

from terminal.cli import print_greyed_out

def load_nist_data():
    cache_dir = 'dataset'
    cache_file_compressed = os.path.join(cache_dir, 'CVE-all.json.xz')
    cache_duration = 86400  # 24 hours

    if not os.path.exists(cache_dir):
        try:
            os.makedirs(cache_dir)
            print_greyed_out(f"[+] NIST_DATA_LOADER: Created cache directory at '{cache_dir}'.")
        except Exception as e:
            print_greyed_out(f"[!] NIST_DATA_LOADER: Failed to create cache directory '{cache_dir}': {e}")

    def is_cache_valid():
        if os.path.exists(cache_file_compressed):
            cache_mtime = os.path.getmtime(cache_file_compressed)
            current_time = time.time()
            return (current_time - cache_mtime) < cache_duration
        return False

    def download_and_cache():
        try:
            print_greyed_out("[*] NIST_DATA_LOADER: Downloading NVD CVE JSON feed...")
            response = httpx.get(
                "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-all.json.xz",
                timeout=30,
                follow_redirects=True
            )
            if response.status_code == 200:
                with open(cache_file_compressed, "wb") as f:
                    f.write(response.content)
                print_greyed_out("[+] NIST_DATA_LOADER: Downloaded and cached NVD CVE JSON feed.")
            else:
                print_greyed_out(f"[!] NIST_DATA_LOADER: Failed to download NVD CVE feed. Status code: {response.status_code}")
        except Exception as e:
            print_greyed_out(f"[!] Error downloading NVD CVE feed: {e}")

    if not is_cache_valid():
        download_and_cache()

    try:
        print_greyed_out("[*] NIST_DATA_LOADER: Loading NIST CVE data into memory...")
        with lzma.open(cache_file_compressed, "rt", encoding="utf-8") as f:
            data = json.load(f)
        print_greyed_out("[+] NIST_DATA_LOADER: NIST CVE data loaded into memory.")
        return data
    except Exception as e:
        print_greyed_out(f"[!] NIST_DATA_LOADER: Error loading NIST data: {e}")
        return {}
