import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from backend.core.logger import CTILogger

# Ensure .env is loaded
load_dotenv()

class RansomwareMonitorFeed:
    def __init__(self, config: dict = None):
        """
        RansomwareMonitor: Configured via .env for Tor stability and real parsing.
        """
        self.config = config or {}
        self.logger = CTILogger.get_logger("RansomwareMonitor")
        
        # Build session using environment variables as defaults
        self.session = self._build_tor_session()

    def _build_tor_session(self):
        """Creates a session configured for .onion high-latency stability."""
        session = requests.Session()
        
        # Pull proxy from config dict or .env file
        proxy_url = self.config.get("TOR_SOCKS_PROXY") or os.getenv("TOR_SOCKS_PROXY", "socks5h://127.0.0.1:9050")
        
        proxies = {
            "http": proxy_url,
            "https": proxy_url
        }
        
        # Retry strategy: Increased for Tor's 'General SOCKS server failure' errors
        max_retries = int(self.config.get("max_retries") or os.getenv("SCRAPER_RETRIES", 5))
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=3, 
            status_forcelist=[429, 500, 502, 503, 504]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.proxies = proxies
        
        # Standardize headers to look like Tor Browser
        ua = self.config.get("user_agent") or os.getenv("USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0")
        session.headers.update({
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        })
        return session

    def _parse_victims(self, html_content, source_name):
        """Extracts victim names based on site-specific HTML structure."""
        victims = []
        soup = BeautifulSoup(html_content, 'html.parser')
        try:
            if "lockbit" in source_name.lower():
                # LockBit typical selectors
                items = soup.select(".post-block .post-title, .post-title")
                victims = [i.get_text(strip=True) for i in items]
            elif "everest" in source_name.lower():
                # Everest typical selectors
                items = soup.select("article h2, .entry-title")
                victims = [i.get_text(strip=True) for i in items]
            else:
                # Fallback generic parsing
                items = soup.find_all(['h2', 'h3'])
                victims = [i.get_text(strip=True) for i in items if len(i.get_text()) > 3]
        except Exception as e:
            self.logger.error(f"Parsing error for {source_name}: {e}")
        return list(set(victims))

    def fetch(self):
        """Fetches and parses ransomware leak data."""
        results = {"detections": {}}
        sources = self.config.get("sources", {})

        for name, url in sources.items():
            try:
                timeout = int(self.config.get("timeout") or os.getenv("SCRAPER_TIMEOUT", 90))
                response = self.session.get(url, timeout=timeout)
                
                if response.status_code == 200:
                    victims = self._parse_victims(response.text, name)
                    results["detections"][name] = {
                        "url": url,
                        "count": len(victims),
                        "status_code": 200,
                        "victims": victims 
                    }
                else:
                    results["detections"][name] = {"url": url, "count": 0, "status_code": response.status_code, "victims": []}

            except Exception as e:
                self.logger.error(f"Fetch failed for {name}: {e}")
                results["detections"][name] = {"url": url, "count": 0, "status_code": "ERROR", "victims": []}
                
        return results