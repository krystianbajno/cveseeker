from typing import List
from services.api.source import Source


class SearchManager:
    def __init__(self, sources: List[Source]):
        self.sources = sources
        
    def search(self, keywords):
        results = []
        for source in self.sources:
                vulnerabilities = source.search(keywords)
                for vulnerability in vulnerabilities:
                    print(vulnerability)
        
        return results
        