from stem import Signal
from stem.control import Controller
import requests
import time
from bs4 import BeautifulSoup

class RansomwareMonitorFeed:
    """
    Dark web ransomware monitor feed.
    Updated to use Tor Browser Ports (9150/9151).
    """

    def __init__(self, config: dict, logger):
        self.config = config
        self.logger = logger

        # TOR BROWSER DEFAULT PORTS:
        # SOCKS Proxy: 9150
        # Control Port: 9151
        socks_proxy = self.config.get("TOR_SOCKS_PROXY", "socks5h://127.0.0.1:9150")
        
        self.session = requests.Session()
        self.session.proxies = {
            "http": socks_proxy,
            "https": socks_proxy,
        }

    def _refresh_tor_circuit(self):
        """Forces Tor Browser to get a new Circuit via Port 9151."""
        try:
            # Tor Browser uses 9151 for control
            with Controller.from_port(port=9151) as controller:
                # Tor Browser typically doesn't require a password/cookie 
                # if it is already authenticated by the UI
                controller.authenticate()  
                controller.signal(Signal.NEWNYM)
            self.logger.info("Tor Browser circuit refreshed successfully.")
            time.sleep(5) 
        except Exception as e:
            self.logger.error(f"Could not refresh Tor Browser circuit: {e}")

    def fetch(self) -> dict:
        """Fetch ransomware victim data using Tor Browser proxy."""
        results = {"detections": {}}
        sources = self.config.get("sources", {})

        for name, url in sources.items():
            success = False
            for attempt in range(2): 
                try:
                    # Onion sites are slow; 90s timeout is good
                    response = self.session.get(url, timeout=90)
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
                    else:
                        self.logger.warning(f"Source {name} returned status {response.status_code}")
                except Exception as e:
                    self.logger.warning(f"Attempt {attempt + 1} failed for {name}: {e}")

                if attempt == 0:
                    self._refresh_tor_circuit()

            if not success:
                results["detections"][name] = {
                    "url": url, "count": 0, "status_code": "FAILED", "victims": [],
                }
        return results

    def _parse_victims(self, html: str, source_name: str):
        """Extracts victim names based on site-specific HTML structure."""
        soup = BeautifulSoup(html, 'html.parser')
        victims = []

        try:
            name_lower = source_name.lower()
            
            # 1. LockBit Logic
            if "lockbit" in name_lower:
                tags = soup.select(".post-title, .post-block__title, h3")
                victims = [t.get_text(strip=True) for t in tags if t.get_text(strip=True)]

            # 2. Everest Logic
            elif "everest" in name_lower:
                tags = soup.find_all(['h2', 'h3'])
                victims = [t.get_text(strip=True) for t in tags if len(t.get_text(strip=True)) > 2]

            # 3. Generic Fallback for other groups
            else:
                tags = soup.find_all(['h1', 'h2', 'h3'])
                victims = [t.get_text(strip=True) for t in tags if 3 < len(t.get_text(strip=True)) < 100]

        except Exception as e:
            self.logger.error(f"Parsing error for {source_name}: {e}")

        return list(set([v for v in victims if v]))