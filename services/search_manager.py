from typing import List
from services.api.source import Source

class SearchManager:
    def __init__(self, sources: List[Source]):
        self.sources = sources
        
    def search(self, keywords, max_results):
        results = []
        for source in self.sources:
            
            vulnerabilities = source.search(keywords, max_results)
            
            for vulnerability in vulnerabilities:
                results.append(vulnerability)
                        
        for result in results:
            print(result)
 
        return results
        