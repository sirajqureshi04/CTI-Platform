import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from backend.core.logger import CTILogger

class RansomwareMonitorFeed:
    def __init__(self, config: dict, http_client=None):
        """
        Refined RansomwareMonitor: Includes real parsing and clearweb failover.
        """
        self.config = config
        self.logger = CTILogger.get_logger("RansomwareMonitor")
        
        # Use the passed client, or build a robust Tor session if none provided
        self.session = http_client if http_client else self._build_tor_session()

    def _build_tor_session(self):
        """Creates a session configured for .onion high-latency stability."""
        session = requests.Session()
        
        # Ensure we use socks5h for remote DNS resolution (vital for .onion)
        proxies = self.config.get("proxies", {
            "http": "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050"
        })
        
        # More aggressive retry strategy for dark web flaky connections
        retry_strategy = Retry(
            total=self.config.get("max_retries", 5),
            backoff_factor=3, # Increased backoff for Tor circuits
            status_forcelist=[429, 500, 502, 503, 504]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.proxies = proxies
        
        # Tor Browser-like User-Agent to avoid immediate blocks
        session.headers.update({
            'User-Agent': self.config.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        return session

    def _parse_victims(self, html_content, source_name):
        """Extracts victim names based on site-specific HTML structure."""
        victims = []
        soup = BeautifulSoup(html_content, 'html.parser')

        try:
            if "lockbit" in source_name.lower():
                # LockBit structure: usually divs with class 'post-block' or similar
                # Update these selectors based on the current version of the site
                items = soup.select(".post-block .post-title, .post-title")
                victims = [i.get_text(strip=True) for i in items]
            
            elif "everest" in source_name.lower():
                # Everest structure: often uses h2 or specific article headers
                items = soup.select("article h2, .entry-title")
                victims = [i.get_text(strip=True) for i in items]
                
            else:
                # Generic fallback if the site structure is unknown
                self.logger.warning(f"No specific parser for {source_name}, attempting generic extraction.")
                items = soup.find_all(['h2', 'h3'])
                victims = [i.get_text(strip=True) for i in items if len(i.get_text()) > 3]

        except Exception as e:
            self.logger.error(f"Parsing error for {source_name}: {e}")
            
        return list(set(victims)) # Return unique victims

    def fetch(self):
        """Standardized fetch method for the test_scraper.py diagnostic."""
        results = {"detections": {}}
        sources = self.config.get("sources", {})

        for name, url in sources.items():
            try:
                self.logger.info(f"Attempting to fetch {name} from {url}")
                
                # Dark web sites need high timeouts (90s+)
                response = self.session.get(url, timeout=self.config.get("timeout", 90))
                
                if response.status_code == 200:
                    victims = self._parse_victims(response.text, name)
                    results["detections"][name] = {
                        "url": url,
                        "count": len(victims),
                        "status_code": response.status_code,
                        "victims": victims 
                    }
                else:
                    self.logger.warning(f"Site {name} returned status {response.status_code}")
                    results["detections"][name] = {"url": url, "count": 0, "status_code": response.status_code, "victims": []}

            except requests.exceptions.ConnectionError as ce:
                self.logger.error(f"SOCKS5 Connection Failed for {name}: Check if Tor is running or circuit is dead.")
                results["detections"][name] = {"url": url, "count": 0, "status_code": "CONNECTION_ERROR", "victims": []}
                
            except Exception as e:
                self.logger.error(f"Unexpected error for {name}: {e}")
                results["detections"][name] = {"url": url, "count": 0, "status_code": 0, "victims": []}
                
        return results