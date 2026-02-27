from stem import Signal
from stem.control import Controller
import requests
import time
from bs4 import BeautifulSoup
import socket
import socks

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
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",  # Helps prevent 'General SOCKS failure' on slow onion sites
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1"
        })
        
        # Set longer timeouts for onion sites
        self.session.timeout = 180

    def _refresh_tor_circuit(self):
        """Forces Tor Browser to get a new identity via Port 9151."""
        try:
            with Controller.from_port(port=9151) as controller:
                controller.authenticate()  # Tor Browser usually has no password for 9151
                controller.signal(Signal.NEWNYM)
            self.logger.info("Tor circuit refreshed. New identity requested.")
            time.sleep(10)  # Longer sleep to allow circuit to build
        except Exception as e:
            self.logger.error(f"Could not refresh Tor circuit: {e}")

    def _check_tor_connection(self):
        """Verify Tor is actually working before attempting scrape."""
        try:
            # Test with a known working site via Tor
            test_response = self.session.get(
                "https://check.torproject.org/api/ip", 
                timeout=30
            )
            if test_response.status_code == 200:
                data = test_response.json()
                if data.get("IsTor", False):
                    return True
            return False
        except:
            return False

    def fetch(self) -> dict:
        """Fetch data from onion sources with increased timeouts."""
        results = {"detections": {}}
        sources = self.config.get("sources", {})
        
        # First verify Tor is working
        if not self._check_tor_connection():
            self.logger.error("Tor connection not verified. Make sure Tor Browser is running.")
            for name, url in sources.items():
                results["detections"][name] = {
                    "url": url, 
                    "count": 0, 
                    "status_code": "TOR_NOT_CONNECTED", 
                    "victims": [],
                }
            return results

        for name, url in sources.items():
            success = False
            
            # Try up to 3 times for each site
            for attempt in range(3): 
                try:
                    self.logger.info(f"Accessing {name} (Attempt {attempt + 1})...")
                    
                    # Make the request with extended timeout
                    response = self.session.get(
                        url, 
                        timeout=180,  # 3 minute timeout for slow onion sites
                        allow_redirects=True,
                        verify=False  # Skip SSL verification for onion sites
                    )
                    
                    if response.status_code == 200:
                        victims = self._parse_victims(response.text, name)
                        results["detections"][name] = {
                            "url": url,
                            "count": len(victims),
                            "status_code": 200,
                            "victims": victims,
                        }
                        success = True
                        self.logger.info(f"Successfully scraped {name} - Found {len(victims)} victims")
                        break
                    elif response.status_code in [503, 504, 502]:
                        # Service unavailable - site might be under load
                        self.logger.warning(f"{name} returned {response.status_code}, retrying in 30s...")
                        time.sleep(30)
                        
                except requests.exceptions.Timeout:
                    self.logger.warning(f"Timeout for {name} (attempt {attempt + 1})")
                    if attempt < 2:
                        time.sleep(20)
                        self._refresh_tor_circuit()
                        
                except requests.exceptions.ConnectionError as e:
                    self.logger.warning(f"Connection error for {name}: {e}")
                    if attempt < 2:
                        time.sleep(20)
                        self._refresh_tor_circuit()
                        
                except Exception as e:
                    self.logger.warning(f"Attempt {attempt + 1} failed for {name}: {e}")
                    if attempt < 2:
                        time.sleep(10)
                        self._refresh_tor_circuit()

            if not success:
                results["detections"][name] = {
                    "url": url, 
                    "count": 0, 
                    "status_code": "FAILED", 
                    "victims": [],
                }
                self.logger.error(f"All attempts failed for {name}")
                
        return results

    def _parse_victims(self, html: str, source_name: str):
        """Parse victims from HTML content."""
        soup = BeautifulSoup(html, 'html.parser')
        victims = []
        try:
            name_lower = source_name.lower()
            
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()
            
            if "lockbit" in name_lower:
                # LockBit specific selectors
                tags = soup.select(".post-title, .post-block__title, h3, h2, .victim-name, .company-name")
                victims = [t.get_text(strip=True) for t in tags if t.get_text(strip=True) and len(t.get_text(strip=True)) > 3]
                
            elif "everest" in name_lower:
                # Everest specific selectors
                tags = soup.find_all(['h2', 'h3', 'h4', '.victim', '.company'])
                victims = [t.get_text(strip=True) for t in tags if len(t.get_text(strip=True)) > 3]
                
            else:
                # Generic selectors
                tags = soup.find_all(['h1', 'h2', 'h3', 'h4', '.title', '.name'])
                victims = [t.get_text(strip=True) for t in tags if 3 < len(t.get_text(strip=True)) < 100]
                
            # Filter out common false positives
            exclude_words = ['home', 'about', 'contact', 'blog', 'archive', 'search', 'login', 'register']
            victims = [v for v in victims if not any(word in v.lower() for word in exclude_words)]
            
        except Exception as e:
            self.logger.error(f"Parsing error for {source_name}: {e}")
            
        return list(set([v for v in victims if v]))  # Remove duplicates