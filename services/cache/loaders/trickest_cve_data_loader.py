import os
import time
import zipfile
import httpx
from typing import Dict

from terminal.cli import print_greyed_out

CACHE_DIR = "dataset"
REPO_URL = "https://github.com/trickest/cve/archive/refs/heads/main.zip"
CACHE_DURATION = 86400  # 1 day

def load_trickest_cve_data() -> Dict[str, str]:
    cache_dir = CACHE_DIR
    repo_zip_path = os.path.join(cache_dir, "cve-main.zip")
    data = {}

    def ensure_cache_dir():
        if not os.path.exists(cache_dir):
            try:
                os.makedirs(cache_dir)
                print_greyed_out(f"[+] TRICKEST_CVE_DATA_LOADER: Created cache directory at '{cache_dir}'.")
            except Exception as e:
                print_greyed_out(f"[!] TRICKEST_CVE_DATA_LOADER: Failed to create cache directory '{cache_dir}': {e}")

    def is_cache_valid():
        if os.path.exists(repo_zip_path):
            repo_mtime = os.path.getmtime(repo_zip_path)
            current_time = time.time()
            return (current_time - repo_mtime) < CACHE_DURATION
        return False

    def download_repo_as_zip():
        try:
            print_greyed_out("[*] TRICKEST_CVE_DATA_LOADER: Downloading CVE repository as zip...")
            response = httpx.get(REPO_URL, timeout=60, follow_redirects=True)
            if response.status_code == 200:
                with open(repo_zip_path, "wb") as f:
                    f.write(response.content)
                print_greyed_out("[+] CVE repository downloaded successfully.")
            else:
                print_greyed_out(f"[!] TRICKEST_CVE_DATA_LOADER: Failed to download repository. Status code: {response.status_code}")
        except Exception as e:
            print(f"[!] TRICKEST_CVE_DATA_LOADER: Error downloading repository: {e}")

    ensure_cache_dir()

    if not is_cache_valid():
        download_repo_as_zip()

    if not os.path.exists(repo_zip_path):
        print_greyed_out("[!] TRICKEST_CVE_DATA_LOADER: Failed to load CVE repository. Falling back to empty cache.")
        return data

    try:
        print_greyed_out("[*] TRICKEST_CVE_DATA_LOADER: Loading CVE data into memory...")
        temp_cache = {}
        with zipfile.ZipFile(repo_zip_path, "r") as zip_ref:
            for file_name in zip_ref.namelist():
                if file_name.endswith(".md"):
                    parts = file_name.strip().split('/')
                    if len(parts) >= 2:
                        cve_file = parts[-1]
                        cve_id = cve_file.replace(".md", "")
                        with zip_ref.open(file_name) as f:
                            temp_cache[cve_id] = f.read().decode("utf-8")
        data = temp_cache
        print_greyed_out("[+] TRICKEST_CVE_DATA_LOADER: CVE data loaded into memory.")
    except zipfile.BadZipFile:
        print_greyed_out("[!] TRICKEST_CVE_DATA_LOADER: Invalid ZIP file format. Please verify the downloaded repository.")
        data = {}
    except Exception as e:
        print_greyed_out(f"[!] TRICKEST_CVE_DATA_LOADER: Error loading CVE data into memory: {e}")
        data = {}

    return data
