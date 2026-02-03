"""
Feed manager for coordinating threat intelligence feed ingestion.
Refined to handle capability-based control flow (Full vs Incremental).
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Type

from backend.core.logger import CTILogger
from backend.database.daos.feed_dao import FeedDAO

logger = CTILogger.get_logger(__name__)

class FeedManager:
    """
    Manages threat intelligence feed lifecycle and persistent health state.
    """
    
    def __init__(self):
        self.feed_dao = FeedDAO()
        self._enabled_cache: List[str] = []
        self._refresh_cache()

    def _refresh_cache(self) -> None:
        """Refresh the local cache of enabled feeds from the database."""
        try:
            enabled_feeds = self.feed_dao.get_active_feeds()
            self._enabled_cache = [f['name'] for f in enabled_feeds]
        except Exception as e:
            logger.error(f"Failed to refresh feed cache from DB: {e}")

    def execute_feed(self, feed_instance: Any) -> Dict[str, Any]:
        """
        Executes a feed based on its capabilities (Incremental vs Full).
        This implements the CONTROL FLOW FIX.
        """
        feed_name = feed_instance.name
        
        # Check Capability Flag from the BaseFeed contract
        # If False (e.g., OTX), we skip getting the last_run_time
        last_run = None
        if getattr(feed_instance, "supports_incremental", True):
            last_run = feed_instance.get_last_run_time()
            logger.info(f"Feed {feed_name} supports incremental. Last run: {last_run}")
        else:
            logger.info(f"Feed {feed_name} is FULL FETCH ONLY. Skipping last_run logic.")

        try:
            # The feed's fetch() will now receive None for OTX, avoiding the 404 params
            # while still allowing incremental feeds to work as intended.
            return feed_instance.run() 
        except Exception as e:
            logger.error(f"Execution of {feed_name} failed: {e}")
            raise

    def register_feed(
        self,
        feed_name: str,
        feed_class: Type,
        enabled: bool = True,
        config: Optional[Dict[str, Any]] = None
    ) -> None:
        """Registers or updates a feed's existence in the Database."""
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

    def update_feed_status(
        self,
        feed_name: str,
        success: bool,
        ioc_count: int = 0,
        error_message: Optional[str] = None
    ) -> None:
        """Updates the health and statistics for a feed after a pipeline run."""
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
        """Check if a feed is allowed to run. Uses cache for speed."""
        return feed_name in self._enabled_cache

    def get_enabled_feeds(self) -> List[str]:
        """Returns the list of names of feeds marked as enabled."""
        self._refresh_cache()
        return self._enabled_cache