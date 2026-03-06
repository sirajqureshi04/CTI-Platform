import socket
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class VictimProvider:

    def __init__(self):

        # very basic industry mapping example
        self.industry_keywords = {
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

            if parsed.netloc:
                return parsed.netloc

            return website.replace("https://", "").replace("http://", "")

        except Exception:

            return None

    def resolve_ip(self, domain):

        try:

            return socket.gethostbyname(domain)

        except Exception:

            return None

    def detect_industry(self, name):

        if not name:
            return None

        name = name.lower()

        for keyword, industry in self.industry_keywords.items():

            if keyword in name:
                return industry

        return "Unknown"

    def enrich(self, ioc):

        try:

            victim_name = ioc.get("value")
            website = ioc.get("website")

            domain = self.extract_domain(website)

            ip_address = None

            if domain:
                ip_address = self.resolve_ip(domain)

            industry = self.detect_industry(victim_name)

            ioc["enrichment"] = {

                "victim_name": victim_name,
                "website": website,
                "domain": domain,
                "resolved_ip": ip_address,
                "industry_guess": industry,
                "threat_context": "Ransomware victim organization"

            }

        except Exception as e:

            logger.error(f"Victim enrichment failed: {e}")

            ioc["enrichment"] = {
                "error": str(e)
            }

        return ioc