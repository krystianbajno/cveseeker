import threading
from typing import Dict, Callable, Optional

from services.cache.loaders.github_poc_data_loader import load_github_poc_data
from services.cache.loaders.nist_data_loader import load_nist_data
from services.cache.loaders.cisa_kev_data_loader import load_cisa_kev_data
from services.cache.loaders.trickest_cve_data_loader import load_trickest_cve_data

class CacheManager:
    def __init__(self, config: Dict):
        self.config = config
        self.cache_data = {}
        self.cache_events = {}
        self.loading_threads = []
        self.load_caches()

    def load_caches(self):
        providers_config = self.config.get('providers', {})
        enrichment_config = self.config.get('enrichment', {}).get('sources', {})

        provider_loaders = {
            'NistCachedAPI': ('nist_cached', load_nist_data),
            'CISAKEVAPI': ('cisa_kev', load_cisa_kev_data),
            'GitHubCachedAPI': ('github_poc_cached', load_github_poc_data),
        }

        enrichment_loaders = {
            'nist_cached': load_nist_data,
            'cisa_kev': load_cisa_kev_data,
            'github_poc_cached': load_github_poc_data,
            'trickest_cve_github_cached': load_trickest_cve_data,
        }

        loaders_to_use = {}

        for provider_name, enabled in providers_config.items():
            if enabled and provider_name in provider_loaders:
                cache_key, loader_func = provider_loaders[provider_name]
                loaders_to_use[cache_key] = loader_func

        for source_name, enabled in enrichment_config.items():
            if enabled and source_name in enrichment_loaders:
                if source_name not in loaders_to_use:
                    loaders_to_use[source_name] = enrichment_loaders[source_name]

        for cache_key, loader_func in loaders_to_use.items():
            self.cache_events[cache_key] = threading.Event()
            thread = threading.Thread(target=self._load_data, args=(cache_key, loader_func))
            self.loading_threads.append(thread)
            thread.start()

    def _load_data(self, name: str, loader_func: Callable):
        data = loader_func()
        with threading.Lock():
            self.cache_data[name] = data
            self.cache_events[name].set()

    def is_data_ready(self, plugin_name: str) -> bool:
        return self.cache_events.get(plugin_name, threading.Event()).is_set()

    def wait_for_data(self, plugin_name: str, timeout: Optional[float] = None):
        event = self.cache_events.get(plugin_name)
        if event:
            event.wait(timeout=timeout)

    def get_data(self, plugin_name: str):
        return self.cache_data.get(plugin_name)

    def ensure_all_data_loaded(self):
        for thread in self.loading_threads:
            thread.join()
