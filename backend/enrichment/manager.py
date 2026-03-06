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

        self.cve = CVEProvider()
        self.malware = MalwareProvider()
        self.url = URLProvider()
        self.ip = IPProvider()
        self.domain = DomainProvider()
        self.victim = VictimProvider()

    def process_item(self, ioc: dict):

        ioc_type = ioc.get("type")

        try:

            if ioc_type == "cve":
                return self.cve.enrich(ioc)

            elif ioc_type == "malware_family":
                return self.malware.enrich(ioc)

            elif ioc_type == "url":
                return self.url.enrich(ioc)

            elif ioc_type == "ip":
                return self.ip.enrich(ioc)

            elif ioc_type == "domain":
                return self.domain.enrich(ioc)

            elif ioc_type == "ransomware_victim":
                return self.victim.enrich(ioc)

            return ioc

        except Exception as e:

            logger.error(f"Enrichment failed for {ioc.get('value')} : {e}")

            return ioc