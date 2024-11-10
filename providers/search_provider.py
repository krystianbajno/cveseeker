import yaml
from services.search_manager import SearchManager

from services.api.sources.exploitdb import ExploitDBAPI
from services.api.sources.github_advisories import GitHubAdvisoryAPI
from services.api.sources.nist import NistAPI
from services.api.sources.opencve import OpenCVEAPI
from services.api.sources.packetstormsecurity import PacketStormSecurityAPI
from services.api.sources.vulners import VulnersAPI

class SearchProvider():
    def __init__(self, playwright_enabled=False, config_file='config.yaml'):
        self.search_service: SearchManager = None
        self.playwright_enabled = playwright_enabled
        self.config_file = config_file

        self.provider_registry = {
            'NistAPI': NistAPI,
            'PacketStormSecurityAPI': PacketStormSecurityAPI,
            'OpenCVEAPI': OpenCVEAPI,
            'ExploitDBAPI': ExploitDBAPI,
            'GitHubAdvisoryAPI': GitHubAdvisoryAPI,
            'VulnersAPI': VulnersAPI,
        }
        
    def make_service_api(self) -> SearchManager:
        if self.search_service is None:
            self.boot()
        return self.search_service
        
    def boot(self):
        config = self.load_config()
        providers_config = config.get('providers', {})
        enrichment_config = config.get("enrichment", False)
        
        providers = []
        
        for provider_name, enabled in providers_config.items():
            if enabled:
                provider_class = self.provider_registry.get(provider_name)
                if provider_class:
                    providers.append(provider_class())
                else:
                    print(f"[!] Provider '{provider_name}' not found in registry.")
            else:
                print(f"[-] Provider '{provider_name}' is disabled in configuration.")

        if self.playwright_enabled:
            playwright_providers = []
            providers.extend(playwright_providers)
        
        self.search_service = SearchManager(providers, enrichment_enabled=enrichment_config)
        
    def load_config(self):
        try:
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)
                return config
        except FileNotFoundError:
            print(f"[!] Config file '{self.config_file}' not found. Using default settings.")
            return {}
        except yaml.YAMLError as exc:
            print(f"[!] Error parsing config file: {exc}")
            return {}
