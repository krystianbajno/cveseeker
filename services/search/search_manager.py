from typing import List, Dict
from models.vulnerability_intelligence import VulnerabilityIntelligence
from services.api.source import Source
from services.search.engine.collection import collect_results
from services.search.engine.enrichment import is_enrichment_enabled, perform_enrichment
from services.search.engine.filtering import filter_by_severity
from services.search.engine.intelligence import prepare_intelligence_from_vulnerabilities
from services.search.engine.modifiers import prepare_descriptions
from services.search.engine.progress import ProgressManager

class SearchManager:
    def __init__(
        self, 
        sources: List[Source], 
        enrichment_config: Dict, 
        progress_manager: ProgressManager, 
        max_retries: int = 3, 
        retry_delay: int = 5
    ):
        self.sources = sources
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.enrichment_config = enrichment_config
        self.progress_manager = progress_manager

    def search(self, keywords: List[str], max_results: int, desired_severities=[]) -> List[VulnerabilityIntelligence]:
        print(f"[*] Initiating search for: \"{' '.join(keywords)}\" with a maximum of {max_results} results per source.\n")

        results = collect_results(self, keywords, max_results)

        print("[+] Collection process complete.")
        
        results = prepare_intelligence_from_vulnerabilities(results, keywords)

        if is_enrichment_enabled(self.enrichment_config):
            print("\n[*] Initiating enrichment process.")
            results = perform_enrichment(results, self.enrichment_config)
            print("[+] Enrichment process complete.")
        else:
            print("\n[*] No enrichment sources are enabled. Skipping enrichment process.")

        results = prepare_descriptions(results)

        if desired_severities:
            print("\n[*] Filtering for desired severities")
            results = filter_by_severity(results, desired_severities)
            print("\n[+] Filtering process complete")

        self.progress_manager.reset_progress()
        return results

