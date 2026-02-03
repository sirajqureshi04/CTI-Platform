import cloudscraper
from datetime import datetime
from typing import Any, Dict
from backend.core.logger import CTILogger
from backend.feeds.clearweb.base_feed import BaseFeed

logger = CTILogger.get_logger(__name__)

class RansomwareLiveScraper(BaseFeed):
    """
    Scraper for Ransomware.live using cloudscraper to bypass 
    Cloudflare anti-bot protections.
    """
    
    # Target the primary structured endpoints
    GROUPS_URL = "https://data.ransomware.live/groups.json"
    VICTIMS_URL = "https://data.ransomware.live/victims.json"

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(name="ransomware_live", config=config or {})
        # Initialize the stealth scraper
        self.scraper = cloudscraper.create_scraper(
            browser={
                'browser': 'chrome',
                'platform': 'windows',
                'desktop': True
            }
        )

    def fetch(self) -> Dict[str, Any]:
        """Fetches groups and victims in parallel to feed the parser."""
        try:
            logger.info("Fetching structured data from Ransomware.live...")
            
            # 1. Fetch Groups
            groups_resp = self.scraper.get(self.GROUPS_URL)
            groups_resp.raise_for_status()
            groups_data = groups_resp.json()

            # 2. Fetch Victims (Latest)
            victims_resp = self.scraper.get(self.VICTIMS_URL)
            victims_resp.raise_for_status()
            victims_data = victims_resp.json()

            logger.info(f"Retrieved {len(groups_data)} groups and {len(victims_data)} victims.")

            return {
                "source": "ransomware_live",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {
                    "groups": groups_data,
                    "victims": victims_data
                }
            }

        except Exception as e:
            logger.error(f"Ransomware.live fetch failed: {e}")
            raise
