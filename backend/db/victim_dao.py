import json
from typing import Any, Dict, List, Optional
from backend.core.logger import CTILogger
from backend.db.connection import db

logger = CTILogger.get_logger(__name__)

class VictimDAO:
    """
    Data Access Object for victims.
    Optimized for bulk ingestion and connection pooling.
    """

    def _get_cursor(self, connection):
        """Helper to ensure we get a dictionary cursor."""
        try:
            return connection.cursor(dictionary=True)
        except (TypeError, AttributeError):
            import pymysql
            return connection.cursor(pymysql.cursors.DictCursor)

    def save_victims(self, victims: List[Dict[str, Any]], source: str):
        """
        Bulk upsert victims. 
        Ensures we don't duplicate victims if the scraper runs multiple times.
        """
        if not victims:
            return

        conn = db.get_connection()
        if not conn:
            return

        query = """
            INSERT INTO victims (name, domain, group_name, discovered, published, source, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                domain = VALUES(domain),
                metadata = JSON_MERGE_PATCH(metadata, VALUES(metadata))
        """

        try:
            cursor = conn.cursor()
            batch_data = []
            for v in victims:
                batch_data.append((
                    v.get("name"),
                    v.get("domain"),
                    v.get("group_name"),
                    v.get("discovered"),
                    v.get("published"),
                    source,
                    json.dumps(v.get("metadata", {}))
                ))

            cursor.executemany(query, batch_data)
            conn.commit()
            logger.info(f"Successfully upserted {len(batch_data)} victims from {source}")
        except Exception as e:
            logger.error(f"Bulk victim insert failed: {e}")
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

    def get_by_group(self, group_name: str) -> List[Dict[str, Any]]:
        """Get all victims claimed by a specific ransomware group."""
        conn = db.get_connection()
        if not conn: return []
        
        try:
            cursor = self._get_cursor(conn)
            cursor.execute(
                "SELECT * FROM victims WHERE group_name = %s ORDER BY published DESC", 
                (group_name,)
            )
            return cursor.fetchall()
        finally:
            cursor.close()
            conn.close()
