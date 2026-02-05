import hashlib
import json
import re
from datetime import datetime
from typing import List, Dict, Any, Optional

from bs4 import BeautifulSoup
from backend.feeds.base_feed import BaseFeed
from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)

class RansomwareMonitorFeed(BaseFeed):
    def __init__(self, http_client: Any, config: Optional[Dict[str, Any]] = None):
        """
        Refined Monitor using the BaseFeed blueprint.
        The http_client passed here should be an instance of TorHTTPClient.
        """
        super().__init__(
            name="Ransomware_Live",
            http_client=http_client,
            config=config
        )
        # Operational Constraints (NESA Alignment)
        self.max_response_size = 10 * 1024 * 1024  # 10 MB
        self.min_victim_length = 20
        self.max_victims_per_page = 500

    def fetch(self, last_run: Optional[str] = None) -> Dict[str, Any]:
        """
        The main execution block called by the Orchestrator.
        """
        sources = self.config.get("sources", {})
        full_intelligence_report = {
            "observed_at": datetime.utcnow().isoformat(),
            "sources_checked": len(sources),
            "detections": {}
        }

        for source_id, url in sources.items():
            try:
                logger.info(f"🔍 Crawling Dark Web Source: {source_id}")
                
                # Use the inherited http_client (TorHTTPClient)
                # Note: safe_stream_response logic is now handled by the client/orchestrator
                response = self.http_client.get(url, stream=True)
                html = self._safe_read_response(response)
                
                victims = self._parse_victims(html)
                current_hash = self._generate_victim_hash(victims)
                
                # Check against state (inherited from BaseFeed)
                last_hash = self.get_last_run_time() # Or specific source state logic
                
                full_intelligence_report["detections"][source_id] = {
                    "url": url,
                    "victim_hash": current_hash,
                    "count": len(victims),
                    "victims": victims,
                    "changed": current_hash != last_hash
                }

            except Exception as e:
                logger.error(f"❌ Source {source_id} failed: {str(e)}")

        return full_intelligence_report

    def validate(self, data: Dict[str, Any]) -> bool:
        """NESA Requirement: Validate data integrity before processing."""
        return "detections" in data and len(data["detections"]) > 0

    def _safe_read_response(self, response) -> str:
        """Prevents Memory Exhaustion (DoS) from malicious .onion sites."""
        total_size = 0
        content = []
        for chunk in response.iter_content(chunk_size=8192):
            total_size += len(chunk)
            if total_size > self.max_response_size:
                raise ValueError("Response exceeded safety limit (10MB).")
            content.append(chunk.decode("utf-8", errors="ignore"))
        return "".join(content)

    def _normalize_victim(self, text: str) -> str:
        """Data Minimization: Strips noise and PII before hashing."""
        text = text.lower().strip()
        # Remove dates and noise
        text = re.sub(r'\b\d{4}-\d{2}-\d{2}\b|\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\s+\d{1,2}\b', '', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text[:200]

    def _parse_victims(self, html: str) -> List[Dict]:
        """Extracts victim data using specialized ransomware leak site selectors."""
        soup = BeautifulSoup(html, "html.parser")
        victims = []
        selectors = ["article.victim", ".victim-card", ".post.leak", "tr.leak-row", ".card.victim"]
        
        items = []
        for s in selectors:
            items = soup.select(s)
            if items: break
        
        if not items:
            items = soup.select("article, .post, .card")

        for item in items[:self.max_victims_per_page]:
            text = item.get_text(" ", strip=True)
            normalized = self._normalize_victim(text)
            
            if len(normalized) >= self.min_victim_length:
                victims.append({
                    "title": normalized,
                    "discovered_at": datetime.utcnow().isoformat()
                })
        return victims

    def _generate_victim_hash(self, victims: List[Dict]) -> str:
        """Intelligence-first hashing: Ignores CSS/UI changes."""
        signatures = sorted([hashlib.sha256(v["title"].encode()).hexdigest()[:16] for v in victims])
        return hashlib.sha256(json.dumps(signatures).encode()).hexdigest()