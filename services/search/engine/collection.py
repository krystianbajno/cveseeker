from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from typing import List
from models.vulnerability import Vulnerability
from models.vulnerability_intelligence import VulnerabilityIntelligence
from services.api.source import Source
from services.vulnerability_intelligence.enrichment.vulnerability_intelligence_enrichment_manager import VulnerabilityIntelligenceEnrichmentManager

def collect_from_source_with_retries(manager, source: Source, keywords: List[str], max_results: int) -> List[Vulnerability]:
    attempts = 0
    retry_delay = manager.retry_delay
    while attempts <= manager.max_retries:
        try:
            results = source.search(keywords, max_results)
            manager.progress_manager.increment_progress(
                source.__class__.__name__, len(results), len(manager.sources)
            )
            return results
        except Exception as e:
            attempts += 1
            if attempts > manager.max_retries:
                raise e
            print(f"[!] Error with source {source.__class__.__name__}, attempt {attempts}. Retrying in {retry_delay} seconds...")
            time.sleep(retry_delay)
            retry_delay *= 2

def is_enrichment_enabled(config: dict) -> bool:
    return any(config.get('sources', {}).values())

def perform_enrichment(vulnerabilities: List[VulnerabilityIntelligence], config: dict) -> List[VulnerabilityIntelligence]:
    enrichment_manager = VulnerabilityIntelligenceEnrichmentManager(vulnerabilities, config)
    return enrichment_manager.enrich()

def collect_results(manager, keywords: List[str], max_results: int) -> List[Vulnerability]:
    collected_results = []
    with ThreadPoolExecutor(max_workers=256) as executor:
        futures = {
            executor.submit(collect_from_source_with_retries, manager, source, keywords, max_results): source
            for source in manager.sources
        }
        for future in as_completed(futures):
            source = futures[future]
            try:
                results = future.result()
                collected_results.extend(results)
            except Exception as e:
                print(f"[!] Error with source {source.__class__.__name__}: {e}")
    return collected_results
