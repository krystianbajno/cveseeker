from typing import List, Dict
from models.vulnerability_intelligence import VulnerabilityIntelligence
from services.cache.cache_manager import CacheManager
from services.search.engine.enrichment import is_enrichment_enabled, perform_enrichment
from services.search.engine.filtering import filter_by_severity
from services.search.engine.intelligence import prepare_intelligence_from_vulnerabilities
from services.search.engine.modifiers import prepare_descriptions

class PostCollectionPipeline:
    def __init__(self, enrichment_config: Dict, desired_severities: List[str], cache_manager: CacheManager):
        self.enrichment_config = enrichment_config
        self.desired_severities = desired_severities
        self.cache_manager = cache_manager

    def process(self, vulnerabilities: List[VulnerabilityIntelligence], keywords: List[str]) -> List[VulnerabilityIntelligence]:
        results = prepare_intelligence_from_vulnerabilities(vulnerabilities, keywords)

        if is_enrichment_enabled(self.enrichment_config):
            print("\n[*] Initiating enrichment process.")
            results = perform_enrichment(results, self.enrichment_config, self.cache_manager)
            print("[+] Enrichment process complete.")
        else:
            print("\n[*] No enrichment sources are enabled. Skipping enrichment process.")

        results = prepare_descriptions(results)

        if self.desired_severities:
            print("\n[*] Filtering for desired severities.")
            results = filter_by_severity(results, self.desired_severities)
            print("[+] Filtering process complete.")

        return results
