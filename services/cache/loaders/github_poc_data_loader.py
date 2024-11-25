import os
import time
import zipfile
import json
from typing import Dict
import httpx

from services.cache.loaders.loader import ensure_cache_directory, is_cache_valid
from terminal.cli import print_greyed_out

REPO_URL = "https://github.com/nomi-sec/PoC-in-GitHub/archive/refs/heads/master.zip"
CACHE_DURATION = 86400  # 1 day

def load_github_poc_data(config) -> Dict[str, Dict]:
    cache_dir = config.get("cache_dir")
    repo_zip_path = os.path.join(cache_dir, "PoC-in-GitHub.zip")
    data = {}
    name = "GITHUB_POC_DATA_LOADER"
        
    def download_repo_as_zip():
        try:
            print_greyed_out("[*] GITHUB_POC_DATA_LOADER: Downloading GitHub PoC repository as zip...")
            response = httpx.get(REPO_URL, timeout=60, follow_redirects=True)
            if response.status_code == 200:
                with open(repo_zip_path, "wb") as f:
                    f.write(response.content)
                print_greyed_out("[+] GITHUB_POC_DATA_LOADER: GitHub PoC repository downloaded successfully.")
            else:
                print_greyed_out(f"[!] GITHUB_POC_DATA_LOADER: Failed to download repository. Status code: {response.status_code}")
        except Exception as e:
            print_greyed_out(f"[!] GITHUB_POC_DATA_LOADER: Error downloading repository: {e}")

    ensure_cache_directory(cache_dir, name)

    if not is_cache_valid(config, repo_zip_path, CACHE_DURATION):
        download_repo_as_zip()

    if not os.path.exists(repo_zip_path):
        print_greyed_out("[!] GITHUB_POC_DATA_LOADER: Failed to load PoC repository. Falling back to empty cache.")
        return data

    try:
        print_greyed_out("[*] GITHUB_POC_DATA_LOADER: Loading PoC repository into memory...")
        temp_cache = {}
        with zipfile.ZipFile(repo_zip_path, "r") as zip_ref:
            for file_name in zip_ref.namelist():
                if file_name.endswith(".json"):
                    try:
                        temp_cache[file_name] = json.loads(zip_ref.read(file_name).decode('utf-8'))
                    except json.JSONDecodeError as e:
                        print_greyed_out(f"[!] GITHUB_POC_DATA_LOADER: Skipping invalid JSON file '{file_name}': {e}")
        data = temp_cache
        print_greyed_out("[+] GITHUB_POC_DATA_LOADER: GitHub PoC data loaded into memory.")
    except zipfile.BadZipFile:
        print_greyed_out("[!] GITHUB_POC_DATA_LOADER: Invalid ZIP file format. Please verify the downloaded repository.")
        data = {}
    except Exception as e:
        print_greyed_out(f"[!] GITHUB_POC_DATA_LOADER: Error loading PoC repository into memory: {e}")
        data = {}

    return data
