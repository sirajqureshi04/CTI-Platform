"""
Data Access Object for Indicators.
Refined with Deduplication Safety Nets for Full Fetching.
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from backend.core.logger import CTILogger
from backend.db.connection import db

logger = CTILogger.get_logger(__name__)

class IndicatorDAO:
    """
    DAO for IOCs. Optimized for JSON merging and preventing bloat 
    during repeated full-feed fetches.
    """

    def save_indicators(self, indicators: List[Dict[str, Any]], source_name: str):
        """
        Deduplication Safety Net: 
        Uses MySQL JSON_MERGE_PATCH to handle 'Full Fetches' without data loss.
        """
        if not indicators:
            return

        conn = db.get_connection()
        if not conn:
            return

        # SQL Logic:
        # 1. FIND_IN_SET ensures we don't duplicate the source name in the CSV column.
        # 2. JSON_MERGE_PATCH updates existing enrichment keys without wiping others.
        # 3. confidence_score increment rewards persistent threats seen across multiple runs.
        query = """
            INSERT INTO indicators (ioc_type, ioc_value, sources, enrichment, confidence_score)
            VALUES (%s, %s, %s, %s, 50) 
            ON DUPLICATE KEY UPDATE
                sources = IF(FIND_IN_SET(%s, sources), sources, CONCAT(sources, ',', %s)),
                enrichment = JSON_MERGE_PATCH(COALESCE(enrichment, '{}'), VALUES(enrichment)),
                confidence_score = LEAST(confidence_score + 2, 100),
                last_seen = CURRENT_TIMESTAMP
        """

        try:
            cursor = conn.cursor()
            batch_data = []

            for ioc in indicators:
                # Structure the payload to include raw_source for temporary tracking
                enrichment_payload = {
                    "metadata": {
                        "first_ingested": datetime.now().isoformat(),
                        "last_source": source_name
                    },
                    "whois": ioc.get("whois_data"),
                    "reputation": ioc.get("reputation"),
                    "geo": ioc.get("geo_data"),
                    "ai_insight": ioc.get("ai_insight")
                }
                
                # Filter None to save space
                enrichment_payload = {k: v for k, v in enrichment_payload.items() if v is not None}

                batch_data.append((
                    ioc['type'],
                    ioc['value'],
                    source_name,
                    json.dumps(enrichment_payload),
                    source_name, # param for FIND_IN_SET
                    source_name  # param for CONCAT
                ))

            cursor.executemany(query, batch_data)
            conn.commit()
            logger.info(f"✓ Saved {len(batch_data)} IOCs from {source_name}. Deduplication logic applied.")
            
        except Exception as e:
            logger.error(f"Database save failed: {e}")
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

    def cleanup_old_raw_data(self, days: int = 7):
        """
        Temporary Data Strategy:
        Removes raw enrichment fields older than X days to prevent DB bloat.
        """
        query = """
            UPDATE indicators 
            SET enrichment = JSON_REMOVE(enrichment, '$.raw_source_data')
            WHERE last_seen < DATE_SUB(NOW(), INTERVAL %s DAY)
        """
        # Execute cleanup logic...
        