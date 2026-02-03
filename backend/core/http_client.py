"""
HTTP client module with Cloudflare bypass, rate limiting, and session management.
Refined for enhanced error logging and parameter isolation.
"""
import time
import random
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests
import cloudscraper
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)

class SecureHTTPClient:
    """
    Refined HTTP client with Cloudflare bypass and robust error diagnostic logging.
    """
    
    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        rate_limit_delay: float = 2.0
    ):
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self._last_request_time: Dict[str, float] = {}
        
        # 1. Standard Session for APIs
        self.standard_session = requests.Session()
        
        # 2. Cloudflare-ready Scraper
        self.cloudflare_scraper = cloudscraper.create_scraper(
            browser={'browser': 'chrome', 'platform': 'windows', 'desktop': True}
        )
        
        # Compatibility property
        self.session = self.standard_session
        
        # Configure Retries
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.standard_session.mount("https://", adapter)
        
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
        ]

    def _get_random_ua(self) -> str:
        return random.choice(self.user_agents)

    def _enforce_rate_limit(self, url: str):
        domain = urlparse(url).netloc
        now = time.time()
        if domain in self._last_request_time:
            elapsed = now - self._last_request_time[domain]
            if elapsed < self.rate_limit_delay:
                sleep_time = (self.rate_limit_delay - elapsed) + random.uniform(0.5, 1.5)
                time.sleep(sleep_time)
        self._last_request_time[domain] = time.time()

    def fetch(self, url: str, bypass_cloudflare: bool = False, **kwargs) -> requests.Response:
        """
        Unified fetch method with explicit parameter isolation and diagnostic logging.
        """
        self._enforce_rate_limit(url)
        
        # Fresh headers for every request
        headers = kwargs.get("headers", {}).copy()
        if "User-Agent" not in headers:
            headers["User-Agent"] = self._get_random_ua()
        kwargs["headers"] = headers

        # Diagnostic info for logging
        params = kwargs.get("params", {})
        
        try:
            if bypass_cloudflare or "ransomware.live" in url:
                response = self.cloudflare_scraper.get(url, timeout=self.timeout, **kwargs)
            else:
                response = self.standard_session.get(url, timeout=self.timeout, **kwargs)
            
            # Explicitly check for 404/403 to provide better debugging
            if response.status_code in [403, 404]:
                logger.error(f"HTTP {response.status_code} Error | URL: {url} | Params: {params}")
            
            response.raise_for_status()
            return response

        except requests.exceptions.HTTPError as e:
            # OPTIONAL BUT IMPORTANT: Log full details on failure
            logger.error(f"Request Failed: {url} | Status: {e.response.status_code} | Params: {params}")
            raise
        except Exception as e:
            logger.error(f"Network Error: {url} | Error: {str(e)}")
            raise

    def get(self, url: str, **kwargs) -> requests.Response:
        """Alias for fetch() for compatibility."""
        bypass_cloudflare = kwargs.pop("bypass_cloudflare", False)
        return self.fetch(url, bypass_cloudflare=bypass_cloudflare, **kwargs)

    def close(self):
        self.standard_session.close()
        self.cloudflare_scraper.close()