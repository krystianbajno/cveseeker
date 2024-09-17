from services.api.sources.nist import NistAPI
from services.search_manager import SearchManager

class SearchProvider():
    def __init__(self):
        self.search_service: SearchManager = None

    def make_service_api(self) -> SearchManager:
        if self.search_service == None:
            self.boot()
            
        return self.search_service
    
    def boot(self):
        providers = [
            NistAPI()
        ]

        self.search_service = SearchManager(providers)
        
        
