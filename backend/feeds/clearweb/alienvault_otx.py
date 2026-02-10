"""
AlienVault OTX feed with incremental loading.
"""

from typing import Any, Dict, Optional
from datetime import datetime, timedelta

from backend.core.logger import CTILogger
from backend.feeds.clearweb.base_feed import BaseFeed

logger = CTILogger.get_logger(__name__)

class AlienVaultOTXFeed(BaseFeed):
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    def __init__(self, api_key: Optional[str] = None, config: Dict[str, Any] = None):
        self.api_key = api_key or (config.get("api_key") if config else None)
        super().__init__(name="alienvault_otx", config=config or {})
        
        if self.api_key:
            self.http_client.session.headers["X-OTX-API-KEY"] = self.api_key

    def fetch(self, last_run: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch data modified since last_run_time.
        Args:
            last_run_time: ISO format timestamp (e.g., "2023-10-27T10:00:00")
        """
        data = {"pulses": []}
        
        # Define the pulse source
        pulse_endpoint = "/pulses/subscribed" if self.api_key else "/pulses/public"
        url = f"{self.BASE_URL}{pulse_endpoint}"
        
        # Setup the 'Modified Since' filter
        # If no last_run is provided, default to last 24 hours
        if not last_run:
            last_run = (datetime.now() - timedelta(days=1)).isoformat()
            
        params = {
            "modified_since": last_run,
            "limit": self.config.get("limit", 100)
        }

        try:
            logger.debug(f"Fetching OTX pulses modified since {last_run}")
            response = self.http_client.get(url, params=params)
            response.raise_for_status()
            
            payload = response.json()
            data["pulses"] = payload.get("results", [])
            
            # Note: OTX results are paginated. For a high-volume feed, 
            # you might need to loop through payload['next']
            
            logger.info(f"Fetched {len(data['pulses'])} new/updated pulses")
            
        except Exception as e:
            logger.error(f"Incremental fetch failed: {e}")

        return {
            "source": "alienvault_otx",
            "timestamp": datetime.now().isoformat(),
            "data": data
        }

    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate AlienVault OTX feed data structure."""
        if not isinstance(data, dict):
            logger.error("Data is not a dictionary")
            return False
        
        if data.get("source") != "alienvault_otx":
            logger.error("Invalid source identifier")
            return False
        
        inner_data = data.get("data", {})
        if not isinstance(inner_data, dict):
            logger.error("Data field is missing or not a dictionary")
            return False
        
        pulses = inner_data.get("pulses", [])
        if not isinstance(pulses, list):
            logger.error("Pulses data is not a list")
            return False
        
        return True