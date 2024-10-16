import datetime
from typing import List
from models.vulnerability import Vulnerability
from models.vulnerability_intelligence import VulnerabilityIntelligence
from services.api.source import Source
from concurrent.futures import ThreadPoolExecutor, as_completed

from services.vulnerability_intelligence.processors.vulnerability_intelligence_processor import VulnerabilityIntelligenceProcessor

class SearchManager:
    def __init__(self, sources: List[Source]):
        self.sources = sources

    def search(self, keywords: List[str], max_results: int):
        results = []

        print(f"[*] Searching for \"{' '.join(keywords)}\", {max_results} per source.")
        
        with ThreadPoolExecutor(max_workers=256) as executor:
            futures = [
                executor.submit(self.__future_collect, source, keywords, max_results)
                for source in self.sources
            ]
            
            for future in as_completed(futures):
                try:
                    vulnerabilities = future.result()
                    results.extend(vulnerabilities)
                except Exception as e:
                    print(f"An error occurred: {e}")

        print("[+] Collection complete")

        filtered_vulnerabilities = VulnerabilityIntelligenceProcessor.process(
            vulnerabilities=results,
            search_terms=keywords
        )

        return filtered_vulnerabilities

    def __future_collect(self, source: Source, keywords: List[str], max_results: int) -> List[Vulnerability]:
        results = source.search(keywords, max_results)
        print(f"+ Source {source.__class__.__name__} collection complete with {len(results)} results.")
        return results