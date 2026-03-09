import logging

from backend.enrichment.providers.cve_provider import CVEProvider
from backend.enrichment.providers.malware_provider import MalwareProvider
from backend.enrichment.providers.url_provider import URLProvider
from backend.enrichment.providers.ip_provider import IPProvider
from backend.enrichment.providers.domain_provider import DomainProvider
from backend.enrichment.providers.victim_provider import VictimProvider

logger = logging.getLogger(__name__)


class EnrichmentManager:

    def __init__(self):

        self.providers = {
            "cve": CVEProvider(),
            "malware_family": MalwareProvider(),
            "url": URLProvider(),
            "ip": IPProvider(),
            "domain": DomainProvider(),
            "ransomware_victim": VictimProvider(),
        }

    def process_item(self, ioc: dict):

        ioc_type = ioc.get("type")

        provider = self.providers.get(ioc_type)

        if not provider:
            return ioc

        try:
            return provider.enrich(ioc)

        except Exception as e:

            logger.error(f"Enrichment failed for {ioc.get('value')} : {e}")

            return ioc