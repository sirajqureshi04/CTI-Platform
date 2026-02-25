from stem import Signal
from stem.control import Controller
import requests
import time
from bs4 import BeautifulSoup # Added BeautifulSoup for parsing

class RansomwareMonitorFeed:
    """
    Dark web ransomware monitor feed.
    Fetches .onion victim pages using Tor and refreshes circuit if blocked.
    """

    def __init__(self, config: dict, logger):
        self.config = config
        self.logger = logger

        # Session configured for Tor SOCKS proxy
        self.session = requests.Session()
        self.session.proxies = {
            "http": self.config.get("TOR_SOCKS_PROXY", "socks5h://127.0.0.1:9050"),
            "https": self.config.get("TOR_SOCKS_PROXY", "socks5h://127.0.0.1:9050"),
        }

    def _refresh_tor_circuit(self):
        """Forces Tor to get a new IP/Circuit to bypass blocks."""
        try:
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()  
                controller.signal(Signal.NEWNYM)
            self.logger.info("Tor circuit refreshed. New identity requested.")
            time.sleep(5) 
        except Exception as e:
            self.logger.error(f"Could not refresh Tor circuit: {e}")

    def fetch(self) -> dict:
        """Fetch ransomware victim data from configured onion sources."""
        results = {"detections": {}}
        sources = self.config.get("sources", {})

        for name, url in sources.items():
            success = False
            for attempt in range(2): 
                try:
                    response = self.session.get(url, timeout=90)
                    if response.status_code == 200:
                        # Logic: Use BeautifulSoup to extract victim names
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
                        self.logger.warning(f"{name} returned status {response.status_code}")
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
        """
        Refined parsing logic using BeautifulSoup.
        Extracts victim names based on specific group layouts.
        """
        soup = BeautifulSoup(html, 'html.parser')
        victims = []

        try:
            # 1. LockBit Logic (Typically in post-title or h3)
            if "lockbit" in source_name.lower():
                # Lockbit uses specific div classes for their list
                tags = soup.select(".post-title, .post-block__title, h3")
                victims = [t.get_text(strip=True) for t in tags if t.get_text(strip=True)]

            # 2. Everest Logic (Typically in h2 or specific entry classes)
            elif "everest" in source_name.lower():
                tags = soup.find_all(['h2', 'h3'])
                victims = [t.get_text(strip=True) for t in tags if len(t.get_text(strip=True)) > 2]

            # 3. Generic Fallback
            else:
                # Common pattern: victim names are often the largest headers
                tags = soup.find_all(['h1', 'h2', 'h3'])
                victims = [t.get_text(strip=True) for t in tags if 3 < len(t.get_text(strip=True)) < 100]

        except Exception as e:
            self.logger.error(f"Parsing error for {source_name}: {e}")

        # Clean list: remove duplicates and "None" values
        return list(set([v for v in victims if v]))