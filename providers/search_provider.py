import yaml
from services.api.sources.cisa_kev import CISAKEVAPI

from services.api.sources.exploitdb import ExploitDBAPI
from services.api.sources.github_advisories import GitHubAdvisoryAPI
from services.api.sources.nist import NistAPI
from services.api.sources.nist_cached import NistCachedAPI
from services.api.sources.opencve import OpenCVEAPI
from services.api.sources.packetstormsecurity import PacketStormSecurityAPI
from services.api.sources.rapid7 import RAPID7
from services.api.sources.vulners import VulnersAPI

from services.cache.cache_manager import CacheManager
from services.search.engine.progress_factory import ProgressManagerFactory
from services.search.search_manager import SearchManager
from terminal.cli import print_greyed_out

class SearchProvider:
    def __init__(self, config):
        self.search_service: SearchManager = None
        self.config = config

        self.provider_registry = {
            'NistAPI': NistAPI,
            "NistCachedAPI": NistCachedAPI,
            'PacketStormSecurityAPI': PacketStormSecurityAPI,
            'OpenCVEAPI': OpenCVEAPI,
            'ExploitDBAPI': ExploitDBAPI,
            'GitHubAdvisoryAPI': GitHubAdvisoryAPI,
            'VulnersAPI': VulnersAPI,
            "CISAKEVAPI": CISAKEVAPI,
            "RAPID7": RAPID7
        }
        
    def make_service_api(self) -> SearchManager:
        if self.search_service is None:
            self.boot()
        return self.search_service
            
    def boot(self):
        config = self.config
        providers_config = config.get('providers', {})
        enrichment_config = config.get("enrichment", {})

        cache_manager = CacheManager(config)

        providers = []

        for provider_name, enabled in providers_config.items():
            if enabled:
                provider_class = self.provider_registry.get(provider_name)
                if provider_class:
                    if provider_name in [
                        'NistCachedAPI', 
                        'CISAKEVAPI'
                    ]:
                        providers.append(provider_class(config, cache_manager))
                    else:
                        providers.append(provider_class(config))
                else:
                    print(f"[!] Provider '{provider_name}' not found in registry.")
            else:
                print_greyed_out(f"[-] Provider '{provider_name}' is disabled in configuration.")

        progress_manager_factory = ProgressManagerFactory()
        self.search_service = SearchManager(providers, enrichment_config, progress_manager_factory=progress_manager_factory, cache_manager=cache_manager)
