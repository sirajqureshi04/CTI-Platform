import requests
import re
from bs4 import BeautifulSoup

class OSINTScraper:
    def __init__(self):
        # Updated to 9050 based on your system diagnostics
        self.proxy = "socks5h://127.0.0.1:9050"
        self.proxies = {'http': self.proxy, 'https': self.proxy}
        self.headers = {"User-Agent": "CTI-Platform-Bot/1.0"}
        self.patterns = {
            "ipv4": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            "sha256": r"\b[A-Fa-f0-9]{64}\b",
            "domain": r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b"
        }

    def scrape(self, url: str, use_tor: bool = False) -> dict:
        try:
            proxy_config = self.proxies if (use_tor or ".onion" in url) else None
            res = requests.get(url, proxies=proxy_config, headers=self.headers, timeout=15)
            
            if res.status_code != 200:
                return {"error": f"Status {res.status_code}"}
            
            soup = BeautifulSoup(res.text, "html.parser")
            text = soup.get_text()
            
            results = {}
            for key, pattern in self.patterns.items():
                results[key] = list(set(re.findall(pattern, text)))[:10]
            
            return results
        except Exception as e:
            return {"error": str(e)}