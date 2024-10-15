import math
import httpx
from typing import List
from dateutil import parser as dateutil_parser

from models.vulnerability import Vulnerability
from services.api.source import Source
from services.vulnerabilities.factories.vulnerability_factory import VulnerabilityFactory, DEFAULT_VALUES

class NistAPI(Source):
    def __init__(self):
        self.url = "https://services.nvd.nist.gov/rest/json/cves/2.0?noRejected"
        
    def search(self, keywords: List[str], max_results) -> List[Vulnerability]:
        # scout what is possible
                
        if not max_results:
            max_results = 2000 # Max for NIST API
            
        if max_results > 2000:
            max_results = 2000
            
        results_per_page = max_results

        vulnerabilities = []

        search_string = "%20".join(keywords)
        
        url = self.url + f"&resultsPerPage=1&startIndex=0&keywordSearch={search_string}"
                              
        response = httpx.get(url)
        
        if response.status_code != 200:
            return vulnerabilities

        data = response.json()
        
        total_results = int(data.get("totalResults"))
        pages = math.ceil(total_results / results_per_page)
        
        # get latest
        
        for i in range(2): 
            url = self.url + f"&resultsPerPage={results_per_page}&startIndex={pages - i}&keywordSearch={search_string}"
                        
            response = httpx.get(url)
            
            if response.status_code != 200:
                return vulnerabilities

            data = response.json()
            
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
                
                date_text = cve_data.get("published", DEFAULT_VALUES["date"])

                parsed_date = dateutil_parser.parse(date_text)
                date = parsed_date.strftime('%Y-%m-%d')

                reference_urls = [ref.get("url", DEFAULT_VALUES["url"]) for ref in cve_data.get("references", [])]
                description = cve_data.get("descriptions", [{"value": DEFAULT_VALUES["description"]}])[0].get("value", DEFAULT_VALUES["description"])
                
                vulnerable_components = []
                configurations = cve_data.get("configurations", {})
                
                if isinstance(configurations, dict):
                    nodes = configurations.get("nodes", [])
                    for node in nodes:
                        for cpe_match in node.get("cpeMatch", []):
                            if cpe_match.get("vulnerable", False):
                                vulnerable_components.append(cpe_match.get("criteria", DEFAULT_VALUES["url"]))

                elif isinstance(configurations, list):
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
                        date=date,
                        reference_urls=reference_urls,
                        base_score=base_score,
                        base_severity=base_severity,
                        description=description,
                        vulnerable_components=vulnerable_components
                    )
                )
        
        return vulnerabilities
