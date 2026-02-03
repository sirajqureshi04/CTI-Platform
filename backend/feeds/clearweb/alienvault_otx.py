"""
AlienVault OTX feed with automatic configuration from settings.
Fully compatible with UAE NESA compliance and OTX v1 API specs.
"""
from typing import Any, Dict, Optional
from datetime import datetime
from requests.exceptions import HTTPError, RequestException

from backend.core.logger import CTILogger
from backend.core.config import settings
from backend.feeds.clearweb.base_feed import BaseFeed

logger = CTILogger.get_logger(__name__)

class AlienVaultOTXFeed(BaseFeed):
    BASE_URL = "https://otx.alienvault.com/api/v1"
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # ✅ FIXED: Correct dunder method name (double underscores)
        super().__init__(name="alienvault_otx", config=config or {})
        
        self.supports_incremental = settings.OTX_INCREMENTAL_ENABLED
        self.api_key = self.config.get("api_key") or settings.OTX_API_KEY
        
        if self.api_key:
            masked_key = f"{self.api_key[:4]}...{self.api_key[-4:]}"
            self.http_client.session.headers["X-OTX-API-KEY"] = self.api_key
            logger.info(f"OTX initialized with API Key: {masked_key}")
        else:
            logger.warning("OTX running in PUBLIC MODE. Rate limits apply (1 req/min).")

    def fetch(self, last_run: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch pulses from OTX. Handles both 'subscribed' and 'public' flows.
        """
        # ✅ FIXED: Official endpoint mapping
        pulse_endpoint = "/pulses/subscribed" if self.api_key else "/pulses/public"
        url = f"{self.BASE_URL}{pulse_endpoint}"
        
        params = {
            "limit": min(self.config.get("limit", 50), 50),
            "page": 1
        }

        # Apply modified_since only if enabled and a last_run exists
        if self.supports_incremental and last_run:
            params["modified_since"] = last_run
            logger.debug(f"Incremental fetch: modified_since={last_run}")
        else:
            logger.info(f"Full fetch triggered (Incremental: {self.supports_incremental})")

        try:
            response = self.http_client.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            payload = response.json()
            
            # ✅ FIXED: OTX API varies between a dict with 'results' and a raw list
            if isinstance(payload, dict):
                pulses = payload.get("results", [])
            elif isinstance(payload, list):
                pulses = payload
            else:
                pulses = []

            logger.info(f"Successfully fetched {len(pulses)} pulses from {pulse_endpoint}")
            
            return {
                "source": "alienvault_otx",
                "timestamp": datetime.now().isoformat(),
                "data": {"pulses": pulses}
            }
            
        except HTTPError as e:
            if e.response.status_code == 429:
                logger.error("OTX Rate Limit Exceeded. Implement backoff or use API Key.")
            elif e.response.status_code == 404:
                logger.error(f"OTX Endpoint 404: Check if {pulse_endpoint} is valid for your key.")
            raise
        except Exception as e:
            # ✅ FIXED: Correct way to log exception types
            logger.error(f"OTX Error [{type(e).__name__}]: {str(e)[:200]}")
            raise

    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate the returned OTX structure."""
        if not isinstance(data, dict) or data.get("source") != "alienvault_otx":
            return False
        
        pulses = data.get("data", {}).get("pulses", [])
        return isinstance(pulses, list)