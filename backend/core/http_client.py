"""
HTTP client module with Cloudflare bypass, Tor support, and rate limiting.
Refined for Dark Web (Onion) compatibility and NESA resilience standards.
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
    Refined HTTP client that handles Clearweb (Cloudflare) and Darkweb (Tor) routing.
    """
    
    def __init__(
        self,
        timeout: int = 60,  # Onion sites are slow; higher default timeout
        max_retries: int = 5,
        rate_limit_delay: float = 2.0,
        proxy_url: Optional[str] = None  # To be passed by TorHTTPClient
    ):
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self._last_request_time: Dict[str, float] = {}
        
        self.standard_session = requests.Session()
        
        # 1. Proxy Configuration (Crucial for monitor.py)
        if proxy_url:
            self.standard_session.proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            logger.info(f"SecureHTTPClient routing through proxy: {proxy_url}")
        
        # 2. Cloudflare-ready Scraper (Clearweb only)
        self.cloudflare_scraper = cloudscraper.create_scraper(
            browser={'browser': 'chrome', 'platform': 'windows', 'desktop': True}
        )
        
        # Configure Retries for resilience
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=2.0, # Exponential backoff for slow Onion sites
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.standard_session.mount("https://", adapter)
        self.standard_session.mount("http://", adapter)
        
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0", # Tor Browser UA
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
        ]

    def _enforce_rate_limit(self, url: str):
        """Prevents getting banned by ransomware leak sites."""
        domain = urlparse(url).netloc
        if not domain: return # For onion addresses without netloc
        
        now = time.time()
        if domain in self._last_request_time:
            elapsed = now - self._last_request_time[domain]
            if elapsed < self.rate_limit_delay:
                time.sleep((self.rate_limit_delay - elapsed) + random.uniform(0.5, 2.0))
        self._last_request_time[domain] = time.time()

    def fetch(self, url: str, bypass_cloudflare: bool = False, **kwargs) -> requests.Response:
        """
        Unified fetch. Automatically avoids Cloudflare scraper for .onion addresses.
        """
        self._enforce_rate_limit(url)
        
        headers = kwargs.get("headers", {}).copy()
        if "User-Agent" not in headers:
            headers["User-Agent"] = random.choice(self.user_agents)
        kwargs["headers"] = headers
        kwargs.setdefault("timeout", self.timeout)

        # Intelligence Routing: .onion sites cannot have Cloudflare protection
        is_onion = url.strip().lower().endswith(".onion") or ".onion/" in url
        
        try:
            if (bypass_cloudflare or "ransomware.live" in url) and not is_onion:
                logger.debug(f"Using Cloudflare bypass for {url}")
                response = self.cloudflare_scraper.get(url, **kwargs)
            else:
                # standard_session uses the proxy_url if initialized (Tor)
                response = self.standard_session.get(url, **kwargs)
            
            if response.status_code in [403, 404]:
                logger.error(f"HTTP {response.status_code} | Source: {url}")
            
            response.raise_for_status()
            return response

        except Exception as e:
            logger.error(f"Network Failure: {url} | Error: {str(e)[:100]}")
            raise

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.fetch(url, **kwargs)

    def close(self):
        self.standard_session.close()
        self.cloudflare_scraper.close()