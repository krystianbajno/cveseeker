from services.api.sources.exploitdb import ExploitDBAPI
from services.api.sources.nist import NistAPI
from services.api.sources.opencve import OpenCVEAPI
from services.api.sources.packetstormsecurity import PacketStormSecurityAPI
from services.search_manager import SearchManager

class SearchProvider():
    def __init__(self, playwright_enabled=False):
        self.search_service: SearchManager = None
        self.playwright_enabled = playwright_enabled
        
    def make_service_api(self) -> SearchManager:
        if self.search_service == None:
            self.boot()
            
        return self.search_service
    
    def boot(self):
        
        providers = [
            NistAPI(),
            PacketStormSecurityAPI(),
            OpenCVEAPI(),
            ExploitDBAPI()
        ]
        
        if self.playwright_enabled:
            playwright_providers = []

            providers.extend(playwright_providers)

        self.search_service = SearchManager(providers)