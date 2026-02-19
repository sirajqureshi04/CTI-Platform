#!/usr/bin/env python3
import re
import requests
from datetime import datetime
from typing import Dict, Any, List
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from backend.core.logger import CTILogger

class RansomwareMonitorFeed:
    """
    Core engine for monitoring Dark Web Ransomware Leaks.
    Integrates Single-pass Redaction and Tor-optimized Session management.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = CTILogger.get_logger("RansomwareMonitor")
        self.proxies = config.get("proxies")
        self.timeout = config.get("timeout", 90)
        
        # Initialize the Single-Pass Redaction Master Regex (from our Phase 2 work)
        self.REDACTION_RULES = {
            "CREDENTIALS": r"(?i)\b(password|passwd|pwd)\b\s*[:=\t]\s*[^\s]{4,256}",
            "JWT": r"\beyJ[A-Za-z0-9_-]{10,100}\.[A-Za-z0-9_-]{10,100}\.[A-Za-z0-9_-]{10,500}\b",
            "EMAIL_PASS": r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b\s*[:|\t\s]\s*[^\s]{6,100}",
            "ONION_V3": r"(?:https?://)?\b[a-z2-7]{56}\.onion\b"
        }
        self.master_regex = re.compile("|".join(f"(?P<{k}>{v})" for k, v in self.REDACTION_RULES.items()))

    def _get_session(self) -> requests.Session:
        """Creates a Tor-optimized session with retry backoff."""
        session = requests.Session()
        retry_strategy = Retry(
            total=self.config.get("max_retries", 3),
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.proxies = self.proxies
        session.headers.update({'User-Agent': self.config.get("user_agent")})
        return session

    def redact_data(self, text: str) -> str:
        """Applies Phase 2 redaction to prevent data leakage in dry runs."""
        if not text: return ""
        def _replacer(match):
            for name in self.REDACTION_RULES.keys():
                if match.group(name): return f"[REDACTED_{name}]"
            return "[REDACTED]"
        return self.master_regex.sub(_replacer, text)

    def fetch(self) -> Dict[str, Any]:
        """Main execution loop for fetching onion sources."""
        results = {"detections": {}, "timestamp": datetime.utcnow().isoformat()}
        session = self._get_session()

        for name, url in self.config.get("sources", {}).items():
            try:
                self.logger.info(f"Fetching {name} at {url}")
                response = session.get(url, timeout=self.timeout)
                
                # Logic to parse victims (simulated for diagnostic)
                # In production, you'd call a custom parser here
                raw_content = response.text
                clean_content = self.redact_data(raw_content)

                # Example parsing logic - find 'victims' in the text
                # This should be replaced with your BeautifulSoup logic
                victims = [{"title": "Example Corp"}] if response.status_code == 200 else []

                results["detections"][name] = {
                    "url": url,
                    "status_code": response.status_code,
                    "count": len(victims),
                    "victims": victims,
                    "raw_data_summary": clean_content[:200] # Safe redacted snippet
                }

            except Exception as e:
                self.logger.error(f"Failed to fetch {name}: {str(e)}")
                results["detections"][name] = {"url": url, "status_code": 0, "count": 0, "error": str(e)}

        return results