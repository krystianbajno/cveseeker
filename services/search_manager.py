from typing import List
from services.api.source import Source
from concurrent.futures import ThreadPoolExecutor, as_completed

class SearchManager:
    def __init__(self, sources: List[Source]):
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
        
        return results
