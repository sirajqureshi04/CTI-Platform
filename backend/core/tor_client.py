"""
Specialized Tor client for Dark Web operations.
Refined to align with SecureHTTPClient's fetch/get architecture.
"""
from typing import Any, Dict, Optional
from backend.core.http_client import SecureHTTPClient
from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)

class TorHTTPClient(SecureHTTPClient):
    """
    Specialized client for Dark Web operations.
    Forces all traffic through SOCKS5h to prevent DNS leaks.
    """
    def __init__(self, proxy_url: str = "socks5h://127.0.0.1:9050", **kwargs):
        # We pass the proxy_url to the parent SecureHTTPClient
        # This ensures standard_session.proxies is set correctly for retries
        super().__init__(proxy_url=proxy_url, **kwargs)
        
        # Explicit proxy dict for passing into manual requests if needed
        self.proxies = {
            "http": proxy_url,
            "https": proxy_url
        }
        logger.info(f"🕸️ TorHTTPClient active. Circuit: {proxy_url}")

    def fetch(self, url: str, **kwargs) -> Any:
        """
        Overrides fetch to ensure proxies are always explicitly applied,
        even if the parent session is modified.
        """
        # Ensure proxies are injected into the kwargs for this specific call
        kwargs["proxies"] = self.proxies
        
        # We force bypass_cloudflare to False because .onion sites 
        # do not use Cloudflare and it would break the SOCKS5 routing.
        kwargs["bypass_cloudflare"] = False
        
        return super().fetch(url, **kwargs)

    def get(self, url: str, **kwargs) -> Any:
        """Alias for fetch to maintain compatibility with monitor.py"""
        return self.fetch(url, **kwargs)