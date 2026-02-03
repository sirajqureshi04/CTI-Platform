"""
Malpedia Scraper (Public Access Optimized).
Targets the MISP Galaxy endpoint for bulk metadata retrieval.
"""

from typing import Any, Dict, Optional
from datetime import datetime

from backend.core.logger import CTILogger
from backend.feeds.clearweb.base_feed import BaseFeed

logger = CTILogger.get_logger(__name__)

class MalpediaFeed(BaseFeed):
    """
    Feed for Malpedia public data.
    Uses the MISP Galaxy format to avoid authentication requirements.
    """
    
    # Publicly accessible API endpoint
    GALAXY_URL = "https://malpedia.caad.fkie.fraunhofer.de/api/get/misp"
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize scraper with public settings."""
        super().__init__(
            name="malpedia",
            config=config or {}
        )
        # Note: No auth headers are added.

    def fetch(self, last_run: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch the current malware galaxy from Malpedia.
        Returns a massive JSON object containing all families and metadata.
        
        Args:
            last_run: Optional timestamp for incremental fetching (not used by this feed)
        
        Returns:
            Dictionary containing malware family data
        """
        try:
            logger.info("Initiating bulk fetch from Malpedia (MISP Galaxy format)...")
            
            # Use the http_client from your Base class
            response = self.http_client.get(self.GALAXY_URL)
            
            # Check for authentication errors
            if response.status_code == 401:
                logger.warning(
                    "Malpedia returned 401 Unauthorized. "
                    "The MISP Galaxy endpoint may require authentication. "
                    "Consider using Malpedia API key if available."
                )
                # Return empty data structure instead of raising
                return {
                    "source": "malpedia",
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {
                        "families": [],
                        "metadata": {
                            "error": "Authentication required",
                            "status_code": 401
                        }
                    }
                }
            
            response.raise_for_status()
            raw_payload = response.json()
            
            # The MISP Galaxy format nests data under 'values'
            families = raw_payload.get("values", [])
            
            logger.info(f"Successfully scraped {len(families)} malware families.")

            return {
                "source": "malpedia",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {
                    "families": families,
                    "metadata": {
                        "galaxy_name": raw_payload.get("name"),
                        "description": raw_payload.get("description"),
                        "version": raw_payload.get("version")
                    }
                }
            }
            
        except Exception as e:
            logger.error(f"Malpedia feed failed: {e}")
            raise

    def validate(self, data: Dict[str, Any]) -> bool:
        """
        Validates the MISP Galaxy structure.
        """
        if not data or "data" not in data:
            return False
        
        # Check if this is an authentication error response
        metadata = data["data"].get("metadata", {})
        if metadata.get("error") == "Authentication required":
            logger.warning("Malpedia validation skipped: Authentication required")
            # Return True to allow the feed to complete (but with empty data)
            return True
            
        families = data["data"].get("families", [])
        if not isinstance(families, list):
            logger.error("Malpedia families data is not a list")
            return False
            
        if len(families) == 0:
            logger.warning("Validation warning: No family data found in Malpedia response.")
            # Allow empty list (might be a temporary issue)
            return True
        
        # Check a sample entry for expected keys
        sample = families[0]
        if "value" not in sample or "meta" not in sample:
            logger.error("Malpedia schema change detected. 'value' or 'meta' missing.")
            return False
        
        return True
