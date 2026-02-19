import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from backend.core.logger import CTILogger

class RansomwareMonitorFeed:
    def __init__(self, config: dict, http_client=None):
        """
        Fixed: http_client is now optional to prevent TypeError.
        """
        self.config = config
        self.logger = CTILogger.get_logger("RansomwareMonitor")
        
        # Use the passed client, or build a robust Tor session if none provided
        self.session = http_client if http_client else self._build_tor_session()

    def _build_tor_session(self):
        """Creates a session configured for .onion high-latency stability."""
        session = requests.Session()
        proxies = self.config.get("proxies", {
            "http": "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050"
        })
        
        # Retry strategy for 504 Gateway Timeouts common on the dark web
        retry_strategy = Retry(
            total=self.config.get("max_retries", 3),
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.proxies = proxies
        session.headers.update({
            'User-Agent': self.config.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0")
        })
        return session

    def fetch(self):
        """Standardized fetch method for the test_scraper.py diagnostic."""
        results = {"detections": {}}
        for name, url in self.config.get("sources", {}).items():
            try:
                # Use a high timeout (90s) for dark web sites
                response = self.session.get(url, timeout=self.config.get("timeout", 90))
                results["detections"][name] = {
                    "url": url,
                    "count": 1 if response.status_code == 200 else 0, # Placeholder logic
                    "status_code": response.status_code,
                    "victims": [] 
                }
            except Exception as e:
                self.logger.error(f"Fetch failed for {name}: {e}")
                results["detections"][name] = {"url": url, "count": 0, "status_code": 0}
        return results