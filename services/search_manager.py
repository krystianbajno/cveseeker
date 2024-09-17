from typing import List
from services.api.source import Source


class SearchManager:
    def __init__(self, sources: List[Source]):
        self.sources = sources
        
    def search(self, keywords):
        # todo async
        results = []
        for source in self.sources:
            # todo print who
            source.search(keywords)
            # todo print results
            
        return results
        