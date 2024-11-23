from typing import List
from models.vulnerability import Vulnerability
from services.vulnerability_intelligence.processors.vulnerability_intelligence_processor import VulnerabilityIntelligenceProcessor

def prepare_intelligence_from_vulnerabilities(vulnerabilities: List[Vulnerability], keywords):
    return VulnerabilityIntelligenceProcessor.process(vulnerabilities, keywords)
