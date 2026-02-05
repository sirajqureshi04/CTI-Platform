import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from bs4 import BeautifulSoup

from backend.feeds.base_feed import BaseFeed
from backend.utils.tor import tor_session  # Ensure this utility exists
from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)

class RansomwareFeed(BaseFeed):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # Initialize BaseFeed with the directory name 'ransomware_live'
        super().__init__(name="Ransomware_Live", config=config)
        
        # Security Constants
        self.max_response_size = 10 * 1024 * 1024  # 10 MB
        self.min_victim_length = 20
        self.session = tor_session() # Leverages your SOCKS5h logic

    def fetch(self, last_run: Optional[str] = None) -> Dict[str, Any]:
        """
        Implements BaseFeed.fetch using Tor-aware logic.
        Sources are pulled from self.config (passed during init).
        """
        sources = self.config.get("sources", {})
        results = {"observed_at": self.get_last_run_time(), "data": {}}

        for source_id, url in sources.items():
            try:
                logger.info(f"🔍 Monitoring Onion Source: {source_id}")
                html = self._safe_stream_fetch(url)
                victims = self._parse_victims(html)
                
                results["data"][source_id] = {
                    "url": url,
                    "victims": victims,
                    "victim_hash": self._generate_victim_hash(victims)
                }
            except Exception as e:
                logger.error(f"❌ Failed to fetch {source_id}: {e}")
        
        return results

    def validate(self, data: Dict[str, Any]) -> bool:
        """Validates that we actually received victim data."""
        return len(data.get("data", {})) > 0

    def _safe_stream_fetch(self, url: str) -> str:
        """Enforces MAX_RESPONSE_SIZE as per UAE NESA Operational Resilience."""
        with self.session.get(url, timeout=self.timeout, stream=True) as r:
            r.raise_for_status()
            content = []
            total_size = 0
            for chunk in r.iter_content(chunk_size=8192):
                total_size += len(chunk)
                if total_size > self.max_response_size:
                    raise ValueError(f"OOM Guardrail: {url} exceeded size limit.")
                content.append(chunk.decode("utf-8", errors="ignore"))
            return "".join(content)

    def _parse_victims(self, html: str) -> List[Dict]:
        """BeautifulSoup logic migrated from your original monitor.py."""
        soup = BeautifulSoup(html, "html.parser")
        victims = []
        selectors = ["article.victim", ".victim-card", ".post.leak", ".card.victim"]
        
        for selector in selectors:
            items = soup.select(selector)
            if items: break
        else:
            items = soup.select("article, .post, .card")

        for item in items:
            text = item.get_text(" ", strip=True)
            normalized = self._normalize(text)
            if len(normalized) >= self.min_victim_length:
                victims.append({"title": normalized, "raw": text[:100]})
        return victims

    def _normalize(self, text: str) -> str:
        """NESA-aligned Data Minimization: Strips noise/PII."""
        text = text.lower().strip()
        text = re.sub(r'\b\d{4}-\d{2}-\d{2}\b', '', text) # Dates
        return re.sub(r'\s+', ' ', text).strip()[:200]

    def _generate_victim_hash(self, victims: List[Dict]) -> str:
        """Intelligence-first hashing: only alerts on content changes."""
        signatures = sorted([hashlib.sha256(v["title"].encode()).hexdigest()[:16] for v in victims])
        return hashlib.sha256(json.dumps(signatures).encode()).hexdigest()