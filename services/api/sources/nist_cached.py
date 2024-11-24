from models.vulnerability import Vulnerability
from services.search.nist_cache_manager import get_cve_data_cache
from services.vulnerabilities.factories.vulnerability_factory import VulnerabilityFactory, DEFAULT_VALUES
from dateutil import parser as dateutil_parser
from typing import List

class NistCachedAPI:
    def search(self, keywords: List[str], max_results: int) -> List[Vulnerability]:
        cve_data_cache = get_cve_data_cache()

        if not cve_data_cache:
            print("[!] CVE data is not available. Returning empty results.")
            return []

        vulnerabilities = []
        cve_items = cve_data_cache.get("cve_items", [])

        cve_items.sort(key=lambda item: item.get('published', ''), reverse=True)
        keyword_set = {keyword.lower() for keyword in keywords}

        for item in cve_items:
            cve_id = item.get("id", DEFAULT_VALUES["id"])
            descriptions = item.get("descriptions", [])
            description = next(
                (desc.get("value") for desc in descriptions if desc.get("lang") == "en"), DEFAULT_VALUES["description"]
            )

            published_date = item.get("published", DEFAULT_VALUES["date"])
            parsed_date = dateutil_parser.parse(published_date)
            date = parsed_date.strftime('%Y-%m-%d')

            reference_urls = [ref.get("url", DEFAULT_VALUES["url"]) for ref in item.get("references", [])]

            metrics = item.get("metrics", {}).get("cvssMetricV2", [])
            if metrics:
                metric = metrics[0]
                base_score = str(metric.get("cvssData", {}).get("baseScore", DEFAULT_VALUES["base_score"]))
                base_severity = metric.get("baseSeverity", DEFAULT_VALUES["base_severity"])
            else:
                base_score = DEFAULT_VALUES["base_score"]
                base_severity = DEFAULT_VALUES["base_severity"]

            vulnerable_components = []
            configurations = item.get("configurations", [])

            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable", False):
                            vulnerable_components.append(cpe_match.get("criteria", DEFAULT_VALUES["url"]))

            if not (
                any(keyword in description.lower() for keyword in keyword_set)
                or any(keyword in cve_id.lower() for keyword in keyword_set)
                or any(keyword in url.lower() for keyword in keyword_set for url in reference_urls)
                or any(keyword in component.lower() for keyword in keyword_set for component in vulnerable_components)
            ):
                continue

            vulnerabilities.append(
                VulnerabilityFactory.make(
                    id=cve_id,
                    url="https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-all.json.xz",
                    source=self.__class__.__name__,
                    date=date,
                    reference_urls=reference_urls,
                    base_score=base_score,
                    base_severity=base_severity,
                    description=description,
                    vulnerable_components=vulnerable_components
                )
            )

            if max_results and len(vulnerabilities) >= max_results:
                break

        return vulnerabilities
