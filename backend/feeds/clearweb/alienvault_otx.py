import os
from typing import Any, Dict, Optional, List
from datetime import datetime
from dotenv import load_dotenv

from backend.core.logger import CTILogger
from backend.feeds.clearweb.base_feed import BaseFeed

load_dotenv()
logger = CTILogger.get_logger(__name__)


class AlienVaultOTXFeed(BaseFeed):
    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(
        self,
        api_key: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        config = config or {}

        self.api_key = (
            api_key
            or config.get("OTX_API_KEY")
            or os.getenv("OTX_API_KEY")
        )

        super().__init__(name="alienvault_otx", config=config)

        if self.api_key and len(self.api_key) > 10:
            self.http_client.session.headers["X-OTX-API-KEY"] = self.api_key
            logger.info("OTX API key detected and loaded.")
        else:
            logger.error("No valid OTX_API_KEY found.")

        self.max_pages = config.get("OTX_MAX_PAGES", 3)
        self.page_size = 50

    # --------------------------------------------------
    # Fetch
    # --------------------------------------------------
    def fetch(self, last_run: Optional[str] = None) -> Dict[str, Any]:
        pulses: List[Dict[str, Any]] = []

        if not self.api_key:
            return self._error_response("OTX API key missing.")

        if not self._verify_api_key():
            return self._error_response("OTX API key verification failed.")

        try:
            for page in range(1, self.max_pages + 1):
                url = f"{self.BASE_URL}/pulses/all"
                params = {
                    "limit": self.page_size,
                    "page": page
                }

                response = self.http_client.get(url, params=params)

                if response.status_code != 200:
                    return self._error_response(
                        f"HTTP {response.status_code}: {response.text}"
                    )

                results = response.json().get("results", [])
                if not results:
                    break

                if last_run:
                    results = self._filter_incremental(results, last_run)

                pulses.extend(results)

                if len(results) < self.page_size:
                    break

            logger.info(f"Total pulses fetched: {len(pulses)}")

            return {
                "source": "alienvault_otx",
                "timestamp": datetime.utcnow().isoformat(),
                "success": True,
                "error": None,
                "data": {
                    "pulses": pulses
                }
            }

        except Exception as e:
            logger.error(f"OTX fetch failed: {e}")
            return self._error_response(str(e))

    # --------------------------------------------------
    # Validate (STRUCTURAL VALIDATION ONLY)
    # --------------------------------------------------
    def validate(self, data: Dict[str, Any]) -> bool:
        if not isinstance(data, dict):
            return False

        if not data.get("success"):
            return False

        pulses = data.get("data", {}).get("pulses")

        if pulses is None:
            return False

        if not isinstance(pulses, list):
            return False

        return True  # empty list is VALID

    # --------------------------------------------------
    # Helpers
    # --------------------------------------------------
    def _verify_api_key(self) -> bool:
        try:
            url = f"{self.BASE_URL}/users/me"
            response = self.http_client.get(url)
            return response.status_code == 200
        except Exception:
            return False

    def _filter_incremental(
        self,
        pulses: List[Dict[str, Any]],
        last_run: str
    ) -> List[Dict[str, Any]]:
        try:
            last_run_dt = datetime.fromisoformat(last_run)
        except Exception:
            return pulses

        filtered = []

        for pulse in pulses:
            modified = pulse.get("modified")
            if not modified:
                continue

            try:
                modified_dt = datetime.fromisoformat(modified.replace("Z", "+00:00"))
                if modified_dt > last_run_dt:
                    filtered.append(pulse)
            except Exception:
                continue

        return filtered

    def _error_response(self, message: str) -> Dict[str, Any]:
        logger.error(message)
        return {
            "source": "alienvault_otx",
            "timestamp": datetime.utcnow().isoformat(),
            "success": False,
            "error": message,
            "data": {"pulses": []}
        }