from stem import Signal
from stem.control import Controller
import requests
import time
from bs4 import BeautifulSoup

class RansomwareMonitorFeed:
    """
    Dark web ransomware monitor feed.
    Refined for Tor Browser stability and anonymity headers.
    """

    def __init__(self, config: dict, logger):
        self.config = config
        self.logger = logger
        self.session = requests.Session()

        # Target Tor Browser Ports
        proxy = self.config.get("TOR_SOCKS_PROXY", "socks5h://127.0.0.1:9150")
        self.session.proxies = {"http": proxy, "https": proxy}

        # CRITICAL: Emulate Tor Browser headers to prevent "Unknown Error" (0xf0)
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",  # Helps prevent 'General SOCKS failure' on slow onion sites
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1"
        })

    def _refresh_tor_circuit(self):
        """Forces Tor Browser to get a new identity via Port 9151."""
        try:
            with Controller.from_port(port=9151) as controller:
                controller.authenticate()  # Tor Browser usually has no password for 9151
                controller.signal(Signal.NEWNYM)
            self.logger.info("Tor circuit refreshed. New identity requested.")
            time.sleep(10) # Longer sleep to allow circuit to build
        except Exception as e:
            self.logger.error(f"Could not refresh Tor circuit: {e}")

    def fetch(self) -> dict:
        """Fetch data from onion sources with increased timeouts."""
        results = {"detections": {}}
        sources = self.config.get("sources", {})

        for name, url in sources.items():
            success = False
            # Increased to 3 attempts for dark web stability
            for attempt in range(3): 
                try:
                    self.logger.info(f"Accessing {name} (Attempt {attempt + 1})...")
                    # Increased timeout to 120s for slow onion handshakes
                    response = self.session.get(url, timeout=120) 
                    
                    if response.status_code == 200:
                        victims = self._parse_victims(response.text, name)
                        results["detections"][name] = {
                            "url": url,
                            "count": len(victims),
                            "status_code": 200,
                            "victims": victims,
                        }
                        success = True
                        break
                except Exception as e:
                    self.logger.warning(f"Attempt {attempt + 1} failed for {name}: {e}")
                    if attempt < 2:
                        self._refresh_tor_circuit()

            if not success:
                results["detections"][name] = {
                    "url": url, "count": 0, "status_code": "FAILED", "victims": [],
                }
        return results

    def _parse_victims(self, html: str, source_name: str):
        soup = BeautifulSoup(html, 'html.parser')
        victims = []
        try:
            name_lower = source_name.lower()
            if "lockbit" in name_lower:
                tags = soup.select(".post-title, .post-block__title, h3")
                victims = [t.get_text(strip=True) for t in tags if t.get_text(strip=True)]
            elif "everest" in name_lower:
                tags = soup.find_all(['h2', 'h3'])
                victims = [t.get_text(strip=True) for t in tags if len(t.get_text(strip=True)) > 2]
            else:
                tags = soup.find_all(['h1', 'h2', 'h3'])
                victims = [t.get_text(strip=True) for t in tags if 3 < len(t.get_text(strip=True)) < 100]
        except Exception as e:
            self.logger.error(f"Parsing error for {source_name}: {e}")
        return list(set([v for v in victims if v]))