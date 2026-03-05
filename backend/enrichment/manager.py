import logging

from backend.enrichment.providers.vulnerability import VulnerabilityProvider
from backend.enrichment.providers.malware import MalwareProvider
from backend.enrichment.providers.victim import VictimProvider

logger = logging.getLogger(__name__)


class EnrichmentManager:
    """
    Central enrichment pipeline manager.
    Routes IOC types to the correct provider.
    """

    def __init__(self):
        self.vulnerability = VulnerabilityProvider()
        self.malware = MalwareProvider()
        self.victim = VictimProvider()

    def process_item(self, ioc: dict) -> dict:
        dtype = ioc.get("type")
        value = ioc.get("value", "Unknown")

        try:
            if dtype == "cve":
                return self.vulnerability.enrich(ioc)

            elif dtype in ["malware_family", "url"]:
                return self.malware.enrich(ioc)

            elif dtype == "ransomware_victim":
                return self.victim.enrich(ioc)

            return ioc

        except Exception as e:
            logger.error(f"Enrichment error for {value}: {e}")
            return ioc