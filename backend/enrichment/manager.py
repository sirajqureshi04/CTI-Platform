from backend.enrichment.providers.vulnerability import VulnerabilityProvider
from backend.enrichment.providers.malware import MalwareProvider
from backend.enrichment.providers.victim import VictimProvider

class EnrichmentManager:
    def __init__(self):
        self.vulnerability = VulnerabilityProvider()
        self.malware = MalwareProvider()
        self.victim = VictimProvider()

    def process_item(self, ioc: dict) -> dict:
        dtype = ioc.get("type")
        
        if dtype == "cve":
            return self.vulnerability.enrich(ioc)
        elif dtype in ["malware_family", "url"]:
            return self.malware.enrich(ioc)
        elif dtype == "ransomware_victim":
            return self.victim.enrich(ioc)
            
        return ioc