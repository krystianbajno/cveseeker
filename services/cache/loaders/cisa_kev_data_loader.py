import os
import time
import json
import httpx

from terminal.cli import print_greyed_out

def load_cisa_kev_data():
    cache_dir = 'dataset'
    cache_file = os.path.join(cache_dir, 'cisa_kev_cache.json')
    cache_duration = 600  # 10 minutes

    if not os.path.exists(cache_dir):
        try:
            os.makedirs(cache_dir)
            print_greyed_out(f"[+] CISA_KEV_DATA_LOADER: Created cache directory at '{cache_dir}'.")
        except Exception as e:
            print_greyed_out(f"[!] CISA_KEV_DATA_LOADER: Failed to create cache directory '{cache_dir}': {e}")

    def is_cache_valid():
        if os.path.exists(cache_file):
            cache_mtime = os.path.getmtime(cache_file)
            current_time = time.time()
            return (current_time - cache_mtime) < cache_duration
        return False

    def download_and_cache():
        try:
            print_greyed_out("[*] CISA_KEV_DATA_LOADER: Downloading CISA KEV catalog...")
            response = httpx.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=15
            )
            if response.status_code == 200:
                data = response.json()
                with open(cache_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=4)
                print_greyed_out("[+] CISA_KEV_DATA_LOADER: CISA KEV catalog downloaded and cached.")
                return data
            else:
                print_greyed_out(f"[!] CISA_KEV_DATA_LOADER: Failed to fetch CISA KEV catalog. Status code: {response.status_code}")
        except Exception as e:
            print_greyed_out(f"[!] CISA_KEV_DATA_LOADER: Error fetching CISA KEV data: {e}")
        return {}

    if is_cache_valid():
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            print_greyed_out("[+] CISA_KEV_DATA_LOADER: Loaded CISA KEV data from cache.")
            return data
        except Exception as e:
            print_greyed_out(f"[!] CISA_KEV_DATA_LOADER: Error reading cache file '{cache_file}': {e}")
            return download_and_cache()
    else:
        return download_and_cache()
