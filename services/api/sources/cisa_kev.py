from models.vulnerability import Vulnerability
from services.api.source import Source
from services.cache.cache_manager import CacheManager
from services.vulnerabilities.factories.vulnerability_factory import VulnerabilityFactory
from dateutil import parser as dateutil_parser
from typing import List

class CISAKEVAPI(Source):
    def __init__(self, cache_manager: CacheManager):
        self.cache_manager = cache_manager

    def search(self, keywords: List[str], max_results: int = 10) -> List[Vulnerability]:
        vulnerabilities = []

        self.cache_manager.wait_for_data('cisa_kev')
        
        data = self.cache_manager.get_data('cisa_kev')
        if not data:
            print("[!] CISA KEV data is not available.")
            return []

        try:
            kev_vulnerabilities = data.get("vulnerabilities", [])
            keyword_set = {keyword.lower() for keyword in keywords}

            for item in kev_vulnerabilities:
                cve_id = item.get("cveID")
                if not cve_id:
                    continue

                description = item.get("shortDescription", "N/A")
                if not any(keyword in description.lower() for keyword in keyword_set):
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
                product = item.get("product", "N/A")
                vendor_project = item.get("vendorProject", "N/A")

                vulnerabilities.append(
                    VulnerabilityFactory.make(
                        id=cve_id,
                        source=self.__class__.__name__,
                        url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                        date=date,
                        reference_urls=reference_urls,
                        description=description,
                        vulnerable_components=[product],
                        tags=[vendor_project],
                        weaknesses=weaknesses
                    )
                )

                if max_results and len(vulnerabilities) >= max_results:
                    break

        except Exception as e:
            print(f"[!] Error processing CISA KEV data: {e}")

        return vulnerabilities
