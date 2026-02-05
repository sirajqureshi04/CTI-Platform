"""
Main pipeline orchestration module.
Refined to handle Dark Web Monitors and automated routing to Victim/Indicator DAOs.
"""
from typing import Any, Dict, List, Optional

from backend.core.feed_manager import FeedManager
from backend.core.logger import CTILogger
from backend.database.daos.indicator_dao import IndicatorDAO
from backend.database.daos.victim_dao import VictimDAO
from backend.database.daos.feed_dao import FeedDAO

# Parsers
from backend.parser.malware_parser import MalwareParser
from backend.parser.ransomware_parser import RansomwareParser
from backend.parser.vulnerability_parser import VulnerabilityParser

# Processors
from backend.processors.deduplicator import Deduplicator
from backend.processors.normalizer import IOCNormalizer
from backend.processors.risk_engine import RiskEngine

logger = CTILogger.get_logger(__name__)

class CTIPipeline:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        # 1. Management & Storage
        self.feed_manager = FeedManager()
        self.feed_dao = FeedDAO()
        self.indicator_dao = IndicatorDAO()
        self.victim_dao = VictimDAO()
        
        # 2. Logic Engines
        self.normalizer = IOCNormalizer()
        self.deduplicator = Deduplicator()
        self.risk_engine = RiskEngine()
        
        # 3. Parsers Mapping
        self.parsers = {
            "ransomware": RansomwareParser(),
            "malware": MalwareParser(),
            "vulnerability": VulnerabilityParser()
        }
        logger.info("Initialized CTI pipeline with Dark Web Monitor support")

    def process_feed(self, feed_instance) -> Dict[str, Any]:
        """
        Orchestrates the lifecycle of a single feed.
        Supports both Clearweb (fetch -> parse) and Darkweb (integrated fetch).
        """
        feed_name = feed_instance.name
        logger.info(f"🚀 Processing pipeline for: {feed_name}")
        
        try:
            # 1. Ingestion & Pre-Parsing
            # Darkweb Monitor returns structured 'detections' directly.
            raw_data = feed_instance.fetch()
            
            # 2. Intellectual Routing
            if "ransomware" in feed_name.lower():
                return self._handle_ransomware_flow(feed_instance, raw_data)
            else:
                return self._handle_standard_ioc_flow(feed_instance, raw_data)
            
        except Exception as e:
            logger.error(f"💥 Pipeline failure for {feed_name}: {e}", exc_info=True)
            self.feed_dao.update_stats(feed_name, success=False, error=str(e))
            return {"success": False, "feed_name": feed_name, "error": str(e)}

    def _handle_ransomware_flow(self, feed_instance, data: Dict[str, Any]) -> Dict[str, Any]:
        """Specialized flow for dark web ransomware victims."""
        # The Monitor (refined monitor.py) returns a 'detections' dict
        # We extract all victims across all onion sources
        all_victims = []
        if "detections" in data:
            for source_id, info in data["detections"].items():
                for victim in info.get("victims", []):
                    all_victims.append({
                        "group_name": source_id,
                        "victim_name": victim["title"],
                        "victim_hash": hashlib.sha256(victim["title"].encode()).hexdigest(),
                        "discovery_date": victim.get("discovered_at")
                    })
        
        # Deduplicate and Ingest
        clean_victims = self.deduplicator.deduplicate(all_victims)
        if clean_victims:
            self.victim_dao.bulk_ingest(clean_victims)
            
        # NESA Audit: Save raw JSON evidence
        feed_instance.save_raw_data(data)
        self.feed_dao.update_stats(feed_instance.name, success=True, count=len(clean_victims))
        
        return {"success": True, "feed": feed_instance.name, "count": len(clean_victims), "type": "Victims"}

    def _handle_standard_ioc_flow(self, feed_instance, raw_data: Any) -> Dict[str, Any]:
        """Standard flow for Clearweb IOCs (CISA, OTX, etc.)"""
        parser = self._select_parser(feed_instance.name)
        parsed_data = parser.parse(raw_data)
        
        normalized = self.normalizer.normalize_batch(parsed_data)
        clean_data = self.deduplicator.deduplicate(normalized)
        
        # Score and store
        scored_data = self.risk_engine.score_batch(clean_data)
        self.indicator_dao.upsert_batch(scored_data)
        
        # NESA Audit
        feed_instance.save_raw_data(raw_data)
        self.feed_dao.update_stats(feed_instance.name, success=True, count=len(clean_data))
        
        return {"success": True, "feed": feed_instance.name, "count": len(clean_data), "type": "Indicators"}

    def _select_parser(self, feed_name: str):
        fn = feed_name.lower()
        if any(x in fn for x in ["cisa", "kev", "otx"]): return self.parsers["vulnerability"]
        return self.parsers["malware"]

    def run_all_feeds(self, feed_instances: List) -> Dict[str, Any]:
        """Executes all enabled feeds in sequence."""
        results = []
        for f in feed_instances:
            if self.feed_manager.is_feed_enabled(f.name):
                results.append(self.process_feed(f))
            else:
                logger.info(f"⏩ Skipping disabled feed: {f.name}")
                
        return {
            "execution_time": datetime.now().isoformat(),
            "results": results
        }