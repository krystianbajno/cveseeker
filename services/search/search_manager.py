from typing import List, Dict
from models.vulnerability_intelligence import VulnerabilityIntelligence
from services.api.source import Source
from services.search.engine.collection import collect_results
from services.search.engine.progress_factory import ProgressManagerFactory
from services.search.engine.post_collection_pipeline import PostCollectionPipeline

class SearchManager:
    def __init__(
        self, 
        sources: List[Source], 
        enrichment_config: Dict, 
        progress_manager_factory: ProgressManagerFactory, 
        max_retries: int = 3, 
        retry_delay: int = 5
    ):
        self.sources = sources
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.enrichment_config = enrichment_config
        self.progress_manager_factory = progress_manager_factory

    def search(self, keywords: List[str], max_results: int, desired_severities=[]) -> List[VulnerabilityIntelligence]:
        print(f"[*] Initiating search for: \"{' '.join(keywords)}\" with a maximum of {max_results} results per source.\n")
        
        if not self.sources:
            print("[!] Please enable at least one source")
            return []

        progress_manager = self.progress_manager_factory.create_progress_manager()

        def progress_callback(source_name: str, result_count: int):
            total_sources = len(self.sources)
            progress_manager.report_progress(source_name, total_sources, result_count)

        results = collect_results(
            sources=self.sources, 
            keywords=keywords, 
            max_results=max_results, 
            progress_callback=progress_callback,
            max_retries=self.max_retries, 
            retry_delay=self.retry_delay
        )

        print("[+] Collection process complete.")

        pipeline = PostCollectionPipeline(
            enrichment_config=self.enrichment_config,
            desired_severities=desired_severities
        )
        
        processed_results = pipeline.process(results, keywords)

        progress_manager.reset_progress()

        return processed_results
