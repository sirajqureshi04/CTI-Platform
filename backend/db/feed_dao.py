import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from backend.core.logger import CTILogger
from backend.db.connection import db

logger = CTILogger.get_logger(__name__)

class FeedDAO:
    """
    Data Access Object for feed management.
    Handles persistent state, health tracking, and configuration.
    """

    def _get_cursor(self, connection):
        """Helper to get a dictionary cursor regardless of the driver used."""
        try:
            return connection.cursor(dictionary=True)
        except (TypeError, AttributeError):
            # Fallback for drivers like pymysql that require a specific class
            import pymysql
            return connection.cursor(pymysql.cursors.DictCursor)

    def upsert_feed(self, name: str, feed_type: str, enabled: bool = True, config: Optional[Dict] = None) -> bool:
        """
        Inserts a feed if it doesn't exist, otherwise updates config/enabled status.
        Aligned with FeedManager.register_feed().
        """
        conn = db.get_connection()
        if not conn: return False
        
        try:
            cursor = conn.cursor()
            query = """
                INSERT INTO feeds (name, feed_type, enabled, config) 
                VALUES (%s, %s, %s, %s) 
                ON DUPLICATE KEY UPDATE 
                    feed_type = VALUES(feed_type),
                    enabled = VALUES(enabled),
                    config = VALUES(config)
            """
            config_json = json.dumps(config or {})
            cursor.execute(query, (name, feed_type, enabled, config_json))
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"Upsert failed for feed {name}: {e}")
            return False
        finally:
            cursor.close()
            conn.close()

    def get_active_feeds(self) -> List[Dict[str, Any]]:
        """
        Fetches all feeds marked as enabled. 
        Used by FeedManager to refresh the orchestrator cache.
        """
        conn = db.get_connection()
        if not conn: return []
        
        try:
            cursor = self._get_cursor(conn)
            cursor.execute("SELECT name, feed_type, config FROM feeds WHERE enabled = TRUE")
            return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to fetch active feeds: {e}")
            return []
        finally:
            cursor.close()
            conn.close()

    def update_stats(self, name: str, success: bool, count: int = 0, error: Optional[str] = None, last_run: Optional[datetime] = None):
        """
        Combined logic for mark_run_start and mark_run_complete.
        Updates counters, timestamps, and error messages in one atomic operation.
        """
        conn = db.get_connection()
        if not conn: return
        
        run_time = last_run or datetime.utcnow()
        
        try:
            cursor = conn.cursor()
            if success:
                query = """
                    UPDATE feeds 
                    SET last_run = %s, 
                        last_success = %s, 
                        run_count = run_count + 1,
                        success_count = success_count + 1,
                        total_iocs_collected = total_iocs_collected + %s,
                        last_error = NULL
                    WHERE name = %s
                """
                cursor.execute(query, (run_time, run_time, count, name))
            else:
                query = """
                    UPDATE feeds 
                    SET last_run = %s, 
                        run_count = run_count + 1,
                        last_error = %s, 
                        error_count = error_count + 1 
                    WHERE name = %s
                """
                cursor.execute(query, (run_time, error, name))
            conn.commit()
        except Exception as e:
            logger.error(f"Failed to update stats for {name}: {e}")
        finally:
            cursor.close()
            conn.close()

    def get_all_stats(self) -> List[Dict[str, Any]]:
        """
        Returns summary for the Executive Report / Dashboard.
        """
        conn = db.get_connection()
        if not conn: return []
        
        try:
            cursor = self._get_cursor(conn)
            cursor.execute("""
                SELECT name, enabled, last_run, last_success, 
                       last_error, run_count, success_count, 
                       error_count, total_iocs_collected 
                FROM feeds
            """)
            return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to fetch feed stats: {e}")
            return []
        finally:
            cursor.close()
            conn.close()