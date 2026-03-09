import socket
import logging
from urllib.parse import urlparse
from functools import lru_cache

logger = logging.getLogger(__name__)


class VictimProvider:

    INDUSTRY_KEYWORDS = {
        "bank": "Finance",
        "finance": "Finance",
        "hospital": "Healthcare",
        "clinic": "Healthcare",
        "university": "Education",
        "school": "Education",
        "gov": "Government",
        "energy": "Energy"
    }

    def extract_domain(self, website):

        if not website:
            return None

        try:

            parsed = urlparse(website)

            domain = parsed.netloc if parsed.netloc else website

            domain = domain.replace("www.", "").strip()

            return domain

        except Exception:
            return None

    @lru_cache(maxsize=10000)
    def resolve_ip(self, domain):

        try:

            _, _, ips = socket.gethostbyname_ex(domain)

            return ips

        except socket.gaierror:

            return []

    @lru_cache(maxsize=10000)
    def detect_industry(self, name):

        if not name:
            return "Unknown"

        name = name.lower()

        for keyword, industry in self.INDUSTRY_KEYWORDS.items():

            if keyword in name:
                return industry

        return "Unknown"

    def enrich(self, ioc):

        try:

            victim_name = ioc.get("value")
            website = ioc.get("website")

            domain = self.extract_domain(website)

            ip_addresses = []

            if domain:
                ip_addresses = self.resolve_ip(domain)

            industry = self.detect_industry(victim_name)

            ioc["enrichment"] = {
                "victim_name": victim_name,
                "website": website,
                "domain": domain,
                "resolved_ips": ip_addresses,
                "industry_guess": industry,
                "threat_context": "Ransomware victim organization"
            }

        except Exception as e:

            logger.error(f"Victim enrichment failed: {e}")

            ioc["enrichment"] = {"error": str(e)}

        return ioc