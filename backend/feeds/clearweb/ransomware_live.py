"""
Ransomware.live feed implementation.

Fetches ransomware group activity and victim data from ransomware.live v2 API.
"""

from typing import Any, Dict, Optional
from datetime import datetime

from backend.core.logger import CTILogger
from backend.feeds.clearweb.base_feed import BaseFeed

logger = CTILogger.get_logger(__name__)


class RansomwareLiveFeed(BaseFeed):
    """Feed for ransomware.live threat intelligence using v2 API."""
    
    # Updated to the official API endpoint
    BASE_URL = "https://api.ransomware.live/v2" 
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize Ransomware.live feed."""
        super().__init__(
            name="ransomware_live",
            config=config or {}
        )
    
    def fetch(self, last_run: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch data from ransomware.live API v2.
        
        Args:
            last_run: Optional timestamp for incremental fetching (not used by this feed)
        
        Returns:
            Dictionary containing ransomware group and victim data
        """
        # The 'key' is used for internal organization; the URL is the source.
        endpoints = {
            "groups": f"{self.BASE_URL}/groups",
            "victims": f"{self.BASE_URL}/recentvictims"  # 'recentvictims' is more stable for recurring feeds
        }
        
        data = {}
        
        for key, url in endpoints.items():
            try:
                logger.debug(f"Fetching {key} from ransomware.live")
                # Assumes self.http_client is a wrapper around 'requests'
                response = self.http_client.get(url)
                
                # Check for HTTP errors before parsing
                response.raise_for_status() 
                
                data[key] = response.json()
                logger.info(f"Fetched {len(data[key])} {key} entries")
            except Exception as e:
                logger.error(f"Failed to fetch {key} from {url}: {e}")
                data[key] = []
        
        return {
            "source": "ransomware.live",
            "timestamp": self._get_timestamp(),
            "data": data
        }
    
    def validate(self, data: Dict[str, Any]) -> bool:
        """
        Validate ransomware.live feed data structure.
        """
        if not isinstance(data, dict):
            logger.error("Data is not a dictionary")
            return False
        
        if data.get("source") != "ransomware.live":
            logger.error("Invalid source identifier")
            return False
        
        inner_data = data.get("data")
        if not isinstance(inner_data, dict):
            logger.error("Data field is missing or not a dictionary")
            return False
        
        # Validate that if keys exist, they contain the expected list format
        for category in ["groups", "victims"]:
            if category in inner_data and not isinstance(inner_data[category], list):
                logger.error(f"{category.capitalize()} data is not a list")
                return False
        
        return True
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp in ISO format."""
        return datetime.now().isoformat()

