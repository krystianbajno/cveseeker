import datetime
from typing import List
from models.vulnerability_intelligence import VulnerabilityIntelligence
from services.api.source import Source
from concurrent.futures import ThreadPoolExecutor, as_completed

from services.vulnerability_intelligence.processors.vulnerability_intelligence_processor import VulnerabilityIntelligenceProcessor

class SearchManager:
    def __init__(self, sources: List[Source]) -> VulnerabilityIntelligence:
        self.sources = sources
        
    def search(self, keywords, max_results):
        results = []

        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(source.search, keywords, max_results) for source in self.sources]
            
            for future in as_completed(futures):
                try:
                    vulnerabilities = future.result()
                    results.extend(vulnerabilities)
                except Exception as e:
                    print(f"An error occurred: {e}")
        
        filtered_vulnerabilities = VulnerabilityIntelligenceProcessor.process(
            vulnerabilities=results,
            search_terms=keywords
        )

        return filtered_vulnerabilities
