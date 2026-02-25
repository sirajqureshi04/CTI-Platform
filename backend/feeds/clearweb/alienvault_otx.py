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

        # Priority: explicit param → config → env
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

        # Configurable limits
        self.max_pages = config.get("OTX_MAX_PAGES", 3)
        self.page_size = 50

    # --------------------------------------------------
    # Fetch
    # --------------------------------------------------
    def fetch(self, last_run: Optional[str] = None) -> Dict[str, Any]:
        pulses: List[Dict[str, Any]] = []

        if not self.api_key:
            logger.error("OTX API key required.")
            return self._build_response(pulses)

        # 1️⃣ Verify key
        if not self._verify_api_key():
            logger.error("OTX API key verification failed (403).")
            return self._build_response(pulses)

        # 2️⃣ Fetch pulses from user feed
        username = self._get_username()

        if not username:
            logger.error("Unable to determine OTX username.")
            return self._build_response(pulses)

        logger.info(f"Fetching pulses from user: {username}")

        try:
            for page in range(1, self.max_pages + 1):
                url = f"{self.BASE_URL}/pulses/user/{username}"
                params = {
                    "limit": self.page_size,
                    "page": page
                }

                response = self.http_client.get(url, params=params)

                if response.status_code != 200:
                    logger.error(
                        f"OTX API error {response.status_code}: {response.text}"
                    )
                    break

                results = response.json().get("results", [])
                if not results:
                    break

                # Incremental filtering
                if last_run:
                    results = self._filter_incremental(results, last_run)

                pulses.extend(results)

                if len(results) < self.page_size:
                    break  # No more pages

            logger.info(f"Total pulses fetched: {len(pulses)}")

        except Exception as e:
            logger.error(f"OTX fetch failed: {e}")

        return self._build_response(pulses)

    # --------------------------------------------------
    # Validate
    # --------------------------------------------------
    def validate(self, data: Dict[str, Any]) -> bool:
        pulses = data.get("data", {}).get("pulses", [])
        return isinstance(pulses, list) and len(pulses) > 0

    # --------------------------------------------------
    # Helpers
    # --------------------------------------------------
    def _verify_api_key(self) -> bool:
        """
        Verifies API key using /users/me endpoint.
        """
        try:
            url = f"{self.BASE_URL}/users/me"
            response = self.http_client.get(url)

            if response.status_code == 200:
                logger.info("OTX API key verification successful.")
                return True

            logger.error(f"OTX key verification failed: {response.status_code}")
            return False

        except Exception as e:
            logger.error(f"OTX key verification error: {e}")
            return False

    def _get_username(self) -> Optional[str]:
        """
        Extracts username from /users/me.
        """
        try:
            url = f"{self.BASE_URL}/users/me"
            response = self.http_client.get(url)

            if response.status_code == 200:
                return response.json().get("username")

        except Exception:
            pass

        return None

    def _filter_incremental(
        self,
        pulses: List[Dict[str, Any]],
        last_run: str
    ) -> List[Dict[str, Any]]:
        """
        Filters pulses modified after last_run timestamp.
        """
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

    def _build_response(self, pulses: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "source": "alienvault_otx",
            "timestamp": datetime.utcnow().isoformat(),
            "data": {
                "pulses": pulses
            }
        }