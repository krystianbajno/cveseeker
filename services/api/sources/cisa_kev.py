import os
import time
import json
from typing import List, Dict
import httpx
from dateutil import parser as dateutil_parser

from models.vulnerability import Vulnerability
from services.api.source import Source
from services.vulnerabilities.factories.vulnerability_factory import VulnerabilityFactory

class CISAKEVAPI(Source):
    CACHE_DIR = "cache"
    CACHE_FILE = os.path.join(CACHE_DIR, "cisa_kev_cache.json")
    CACHE_DURATION = 600

    def __init__(self):
        self.url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.ensure_cache_dir()

    def ensure_cache_dir(self):
        if not os.path.exists(self.CACHE_DIR):
            try:
                os.makedirs(self.CACHE_DIR)
                print(f"[*] Created cache directory at '{self.CACHE_DIR}'.")
            except Exception as e:
                print(f"[!] Failed to create cache directory '{self.CACHE_DIR}': {e}")

    def is_cache_valid(self) -> bool:
        if os.path.exists(self.CACHE_FILE):
            cache_mtime = os.path.getmtime(self.CACHE_FILE)
            current_time = time.time()
            if (current_time - cache_mtime) < self.CACHE_DURATION:
                return True
        return False

    def load_cache(self) -> Dict:
        try:
            with open(self.CACHE_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                print("[*] Loaded CISA KEV catalog from cache.")
                return data
        except Exception as e:
            print(f"[!] Error reading CISA KEV cache: {e}")
            return {}

    def update_cache(self, data: Dict):
        try:
            with open(self.CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
                print("[+] CISA KEV catalog downloaded and cached.")
        except Exception as e:
            print(f"[!] Error updating CISA KEV cache: {e}")

    def fetch_data(self) -> Dict:
        try:
            print("[*] Downloading CISA KEV catalog...")
            response = httpx.get(self.url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                self.update_cache(data)
                return data
            else:
                print(f"[!] Failed to fetch CISA KEV catalog. Status code: {response.status_code}")
        except Exception as e:
            print(f"[!] Error fetching CISA KEV data: {e}")
        return {}

    def get_data(self) -> Dict:
        if self.is_cache_valid():
            return self.load_cache()
        else:
            return self.fetch_data()

    def search(self, keywords: List[str], max_results: int) -> List[Vulnerability]:

        vulnerabilities = []
        try:
            data = self.get_data()
            kev_vulnerabilities = data.get("vulnerabilities", [])

            for item in kev_vulnerabilities:
                cve_id = item.get("cveID")
                
                if not cve_id:
                    continue

                date_added = item.get("dateAdded")
                try:
                    parsed_date = dateutil_parser.parse(date_added)
                    date = parsed_date.strftime('%Y-%m-%d')
                except Exception:
                    date = date_added or "N/A"

                notes = item.get("notes", "")
                reference_urls = [url.strip() for url in notes.split(" ; ") if url.strip()]
                weaknesses = item.get("cwes", [])

                vulnerability = VulnerabilityFactory.make(
                    id=cve_id,
                    source=self.__class__.__name__,
                    url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    date=date,
                    reference_urls=reference_urls,
                    description=item.get("shortDescription", "N/A"),
                    vulnerable_components=[item.get("product", "N/A")],
                    tags=[item.get("vendorProject", "N/A")],
                    weaknesses=weaknesses
                )
                vulnerabilities.append(vulnerability)

        except Exception as e:
            print(f"[!] Error processing CISA KEV data: {e}")

        return vulnerabilities
