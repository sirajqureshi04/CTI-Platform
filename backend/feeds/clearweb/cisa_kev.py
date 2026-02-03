"""
CISA KEV (Known Exploited Vulnerabilities) feed implementation.
"""

from typing import Any, Dict, Optional
from datetime import datetime

from backend.core.logger import CTILogger
from backend.feeds.clearweb.base_feed import BaseFeed

logger = CTILogger.get_logger(__name__)

class CISAKEVFeed(BaseFeed):
    """Feed for CISA Known Exploited Vulnerabilities catalog."""
    
    # Authoritative URL for the KEV JSON feed
    KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            name="cisa_kev",
            config=config or {}
        )
    
    def fetch(self, last_run: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch the full CISA KEV catalog.
        Note: CISA does not currently support 'modified_since' on this specific JSON endpoint,
        so we fetch the full list and rely on the processing layer to handle duplicates.
        
        Args:
            last_run: Optional timestamp for incremental fetching (not used by this feed)
        """
        try:
            logger.debug(f"Fetching CISA KEV catalog from {self.KEV_CATALOG_URL}")
            response = self.http_client.get(self.KEV_CATALOG_URL)
            response.raise_for_status()
            
            data = response.json()
            
            # Metadata extraction
            catalog_version = data.get("catalogVersion", "N/A")
            vulnerabilities = data.get("vulnerabilities", [])
            
            logger.info(f"Successfully fetched KEV v{catalog_version} ({len(vulnerabilities)} entries)")
            
            return {
                "source": "cisa_kev",
                "timestamp": datetime.now().isoformat(),
                "data": {
                    "vulnerabilities": vulnerabilities,
                    "count": len(vulnerabilities),
                    "version": catalog_version
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to fetch CISA KEV: {e}")
            raise

    def validate(self, data: Dict[str, Any]) -> bool:
        """Strict validation for CTI data integrity."""
        if not (data and "data" in data):
            return False
            
        vulns = data["data"].get("vulnerabilities", [])
        if not isinstance(vulns, list) or len(vulns) == 0:
            logger.error("KEV data is empty or invalid format")
            return False
            
        # Verify a sample entry for expected schema
        sample = vulns[0]
        required = ["cveID", "vendorProject", "product"]
        if not all(k in sample for k in required):
            logger.error(f"KEV schema mismatch. Missing one of: {required}")
            return False
            
        return True
