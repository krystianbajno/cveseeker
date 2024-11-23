from typing import List
from models.vulnerability_intelligence import VulnerabilityIntelligence
from services.vulnerability_intelligence.enrichment.vulnerability_intelligence_enrichment_manager import VulnerabilityIntelligenceEnrichmentManager

def is_enrichment_enabled(config: dict) -> bool:
    return any(config.get('sources', {}).values())

def perform_enrichment(vulnerabilities: List[VulnerabilityIntelligence], config: dict) -> List[VulnerabilityIntelligence]:
    enrichment_manager = VulnerabilityIntelligenceEnrichmentManager(vulnerabilities, config)
    return enrichment_manager.enrich()
