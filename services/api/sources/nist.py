import httpx
from typing import List

from models.vulnerability import Vulnerability
from services.api.source import Source
from services.vulnerability_factory import VulnerabilityFactory, DEFAULT_VALUES

class NistAPI(Source):
    def __init__(self):
        self.url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="
    
    def search(self, keywords: List[str]) -> List[Vulnerability]:
        search_string = " ".join(keywords)
        response = httpx.get(f"{self.url}{search_string}")
        
        if response.status_code != 200:
            return []

        data = response.json()
        vulnerabilities = []
        
        for vulnerability in data.get("vulnerabilities", []):
            cve_data = vulnerability.get("cve", {})
            metrics = cve_data.get("metrics", {})
            
            cvss_v2_data = None
            base_severity = DEFAULT_VALUES["base_severity"]
            base_score = DEFAULT_VALUES["base_score"]
            
            if "cvssMetricV2" in metrics:
                cvss_v2 = metrics["cvssMetricV2"][0]
                cvss_v2_data = cvss_v2.get("cvssData", {})
                base_score = str(cvss_v2_data.get("baseScore", DEFAULT_VALUES["base_score"]))
                base_severity = cvss_v2.get("baseSeverity", DEFAULT_VALUES["base_severity"])
            
            id = cve_data.get("id", DEFAULT_VALUES["id"])
            reference_urls = [ref.get("url", DEFAULT_VALUES["url"]) for ref in cve_data.get("references", [])]
            description = cve_data.get("descriptions", [{"value": DEFAULT_VALUES["description"]}])[0].get("value", DEFAULT_VALUES["description"])
            
            vulnerable_components = []
            configurations = cve_data.get("configurations", {})
            
            if isinstance(configurations, dict):  # Handle case where configurations is a dictionary
                nodes = configurations.get("nodes", [])
                for node in nodes:
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable", False):
                            vulnerable_components.append(cpe_match.get("criteria", DEFAULT_VALUES["url"]))

            elif isinstance(configurations, list):  # Handle case where configurations is a list
                for config in configurations:
                    nodes = config.get("nodes", [])
                    for node in nodes:
                        for cpe_match in node.get("cpeMatch", []):
                            if cpe_match.get("vulnerable", False):
                                vulnerable_components.append(cpe_match.get("criteria", DEFAULT_VALUES["url"]))

            vulnerabilities.append(
                VulnerabilityFactory.make(
                    id=id,
                    source=self,
                    reference_urls=reference_urls,
                    base_score=base_score,
                    base_severity=base_severity,
                    description=description,
                    vulnerable_components=vulnerable_components
                )
            )
        
        return vulnerabilities
