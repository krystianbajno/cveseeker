import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
from models.vulnerability import Vulnerability
from models.vulnerability_intelligence import VulnerabilityIntelligence
from services.api.source import Source
from services.vulnerability_intelligence.processors.vulnerability_intelligence_processor import VulnerabilityIntelligenceProcessor

from models.vulnerability import Vulnerability
from models.vulnerability_intelligence import VulnerabilityIntelligence
from services.vulnerability_intelligence.enrichment.vulnerability_intelligence_enrichment import VulnerabilityIntelligenceEnrichment
from services.vulnerability_intelligence.processors.vulnerability_intelligence_processor import VulnerabilityIntelligenceProcessor
from typing import List

class SearchManager:
    def __init__(self, sources: List[Source], max_retries: int = 3, retry_delay: int = 5):
        self.sources = sources
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._lock = threading.Lock()
        self._progress_counter = 0

    def search(self, keywords: List[str], max_results: int) -> List[VulnerabilityIntelligence]:
        collected_results = []

        print(f"[*] Initiating search for: \"{' '.join(keywords)}\" with a maximum of {max_results} results per source.\n")

        with ThreadPoolExecutor(max_workers=256) as executor:
            futures = {
                executor.submit(self._collect_from_source_with_retries, source, keywords, max_results): source
                for source in self.sources
            }
            
            for future in as_completed(futures):
                source = futures[future]
                try:
                    results = future.result()
                    collected_results.extend(results)
                except Exception as e:
                    print(f"[!] Error with source {source.__class__.__name__} after retries: {e}")

        print("[+] Collection process complete.")

        processed_results = VulnerabilityIntelligenceProcessor.process(
            vulnerabilities=collected_results,
            search_terms=keywords
        )
        
        print("\n[*] Initiating enrichment process.")

        enriched_results = self._perform_enrichment(processed_results)
        
        print("[+] Enrichment process complete.")

        self._reset_progress()

        return enriched_results

    def _perform_enrichment(self, vulnerability_intelligence_list: List[VulnerabilityIntelligence]) -> List[VulnerabilityIntelligence]:
        enrichment = VulnerabilityIntelligenceEnrichment(vulnerability_intelligence_list)
        return enrichment.enrich()

    def _collect_from_source_with_retries(self, source: Source, keywords: List[str], max_results: int) -> List[Vulnerability]:
        attempts = 0
        retry_delay = self.retry_delay
        initial_retry_delay = retry_delay
        
        while attempts <= self.max_retries:
            try:
                results = source.search(keywords, max_results)
                retry_delay = initial_retry_delay
                self._increment_progress(source, len(results))
                return results
            except Exception as e:
                attempts += 1
                if attempts > self.max_retries:
                    break
                print(f"[!] Error with source {source.__class__.__name__}, attempt {attempts}/{self.max_retries}. Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
                retry_delay = retry_delay * 2

    def _increment_progress(self, source: Source, result_count: int):
        with self._lock:
            self._progress_counter += 1
            print(f"+ Progress: [{self._progress_counter}/{len(self.sources)}] - "
                  f"Source {source.__class__.__name__} collection complete with {result_count} results.")

    def _reset_progress(self):
        self._progress_counter = 0
