"""
Main pipeline orchestration module.
Refined to support MySQL DAOs and automated routing.
"""
from pathlib import Path
from typing import Any, Dict, List, Optional

# Infrastructure & DAOs
from backend.core.feed_manager import FeedManager
from backend.core.logger import CTILogger
from backend.database.daos.indicator_dao import IndicatorDAO
from backend.database.daos.victim_dao import VictimDAO
from backend.database.daos.feed_dao import FeedDAO

# Processors & Intelligence
from backend.parser.malware_parser import MalwareParser
from backend.parser.ransomware_parser import RansomwareParser
from backend.parser.vulnerability_parser import VulnerabilityParser
from backend.processors.deduplicator import Deduplicator
from backend.processors.normalizer import IOCNormalizer
from backend.processors.risk_engine import RiskEngine

logger = CTILogger.get_logger(__name__)

class CTIPipeline:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        # Initialize Management & Storage
        self.feed_manager = FeedManager()
        self.feed_dao = FeedDAO()
        self.indicator_dao = IndicatorDAO()
        self.victim_dao = VictimDAO()
        
        # Initialize Logic Engines
        self.normalizer = IOCNormalizer()
        self.deduplicator = Deduplicator()
        self.risk_engine = RiskEngine()
        
        # Parsers Mapping
        self.parsers = {
            "ransomware": RansomwareParser(),
            "malware": MalwareParser(),
            "vulnerability": VulnerabilityParser()
        }
        logger.info("Initialized CTI pipeline with DAO integration")

    def process_feed(self, feed_instance) -> Dict[str, Any]:
        feed_name = feed_instance.name
        logger.info(f"Processing feed: {feed_name}")
        
        try:
            # 1. Ingestion
            raw_data = feed_instance.fetch()
            
            # 2. Parsing
            parser = self._select_parser(feed_name)
            parsed_data = parser.parse(raw_data)
            
            # 3. Processing (Normalization & Dedup)
            normalized = self.normalizer.normalize_batch(parsed_data)
            clean_data = self.deduplicator.deduplicate(normalized)
            
            # 4. Routing & Storage (The Critical Fix)
            # Route to VictimDAO if ransomware, otherwise IndicatorDAO
            if "ransomware" in feed_name.lower():
                self.victim_dao.bulk_ingest(clean_data)
                storage_type = "Victims"
            else:
                scored_data = self.risk_engine.score_batch(clean_data)
                self.indicator_dao.upsert_batch(scored_data)
                storage_type = "Indicators"

            # 5. Update Feed Stats in DB
            self.feed_dao.update_stats(feed_name, success=True, count=len(clean_data))
            
            return {"success": True, "feed_name": feed_name, "count": len(clean_data), "type": storage_type}
            
        except Exception as e:
            logger.error(f"Failed {feed_name}: {e}")
            self.feed_dao.update_stats(feed_name, success=False, error=str(e))
            return {"success": False, "feed_name": feed_name, "error": str(e)}

    def _select_parser(self, feed_name: str):
        fn = feed_name.lower()
        if "ransomware" in fn: return self.parsers["ransomware"]
        if any(x in fn for x in ["cisa", "kev", "otx"]): return self.parsers["vulnerability"]
        return self.parsers["malware"]

    def run_all_feeds(self, feed_instances: List) -> Dict[str, Any]:
        results = [self.process_feed(f) for f in feed_instances if self.feed_manager.is_feed_enabled(f.name)]
        return {
            "total": len(feed_instances),
            "successful": sum(1 for r in results if r["success"]),
            "results": results
        }