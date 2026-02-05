"""
Refined FeedManager for Modular CTI Architecture.
Handles Tor-based Dark Web monitors and standard Clearweb feeds.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Type

from backend.core.logger import CTILogger
from backend.database.daos.feed_dao import FeedDAO

logger = CTILogger.get_logger(__name__)

class FeedManager:
    def __init__(self):
        self.feed_dao = FeedDAO()
        self._enabled_cache: List[str] = []
        self._refresh_cache()

    def _refresh_cache(self) -> None:
        try:
            enabled_feeds = self.feed_dao.get_active_feeds()
            self._enabled_cache = [f['name'] for f in enabled_feeds]
        except Exception as e:
            logger.error(f"Failed to refresh feed cache from DB: {e}")

    def execute_feed(self, feed_instance: Any) -> Dict[str, Any]:
        """
        Executes a feed, handles Dark Web specifics, and updates state.
        """
        feed_name = feed_instance.name
        
        # 1. Capability Check (NESA Resilience)
        last_run = None
        if getattr(feed_instance, "supports_incremental", True):
            last_run = feed_instance.get_last_run_time()
            logger.info(f"[{feed_name}] Mode: Incremental (Last run: {last_run})")
        else:
            logger.info(f"[{feed_name}] Mode: Full Fetch")

        try:
            # 2. Execution logic
            # For monitor.py, fetch() returns the structured intelligence report
            raw_data = feed_instance.fetch(last_run=last_run)
            
            # 3. Validation (Data Integrity Check)
            if not feed_instance.validate(raw_data):
                raise ValueError(f"Feed {feed_name} failed validation (no data returned)")

            # 4. Persistence (Save to data/raw/ and update last_run)
            # This ensures we have a forensic audit trail in storage/raw/
            save_path = feed_instance.save_raw_data(raw_data)
            logger.info(f"[{feed_name}] Evidence saved to: {save_path.name}")
            
            # 5. Extract Statistics for DB Update
            # If it's the Dark Web monitor, we count the total victims across all sources
            total_items = 0
            if "detections" in raw_data:
                total_items = sum(d["count"] for d in raw_data["detections"].values())
            else:
                summary = feed_instance._extract_data_summary(raw_data)
                total_items = summary.get("total_items", 0)

            # 6. Update Success Stats
            self.update_feed_status(feed_name, success=True, ioc_count=total_items)
            
            # Update internal state file (used for the next hash check)
            feed_instance.save_state(datetime.now().isoformat())
            
            return raw_data

        except Exception as e:
            logger.error(f"💥 Execution of {feed_name} failed: {e}")
            self.update_feed_status(feed_name, success=False, error_message=str(e))
            raise

    def register_feed(self, feed_name: str, feed_class: Type, enabled: bool = True, config: Optional[Dict[str, Any]] = None) -> None:
        try:
            self.feed_dao.upsert_feed(
                name=feed_name,
                feed_type=feed_class.__name__,
                enabled=enabled,
                config=config or {}
            )
            logger.info(f"Registered/Sync'd feed: {feed_name}")
            self._refresh_cache()
        except Exception as e:
            logger.error(f"Failed to register feed {feed_name} in DB: {e}")

    def update_feed_status(self, feed_name: str, success: bool, ioc_count: int = 0, error_message: Optional[str] = None) -> None:
        try:
            self.feed_dao.update_stats(
                name=feed_name,
                success=success,
                count=ioc_count,
                error=error_message,
                last_run=datetime.now()
            )
        except Exception as e:
            logger.error(f"Could not update DB state for {feed_name}: {e}")

    def is_feed_enabled(self, feed_name: str) -> bool:
        return feed_name in self._enabled_cache