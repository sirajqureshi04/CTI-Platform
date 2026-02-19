import re
from typing import Any, Dict, List
from backend.core.logger import CTILogger
from backend.parser.base_parser import BaseParser

logger = CTILogger.get_logger(__name__)

class AlienVaultOTXParser(BaseParser):
    """
    CTI-grade parser for AlienVault OTX Pulses.
    Extracts individual indicators from nested pulse structures.
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            # Factor 1: Name must match your SOURCE_MAP key in deduplicator.py
            name="alienvault_parser", 
            config=config or {}
        )

    def parse(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        items = []
        
        # 1. Access the main data list (AlienVault API usually returns a list of Pulses)
        pulses = raw_data.get("data", [])
        if not pulses and isinstance(raw_data.get("data"), dict):
            # Handle single-pulse ingestion
            pulses = [raw_data["data"]]

        for pulse in pulses:
            pulse_name = pulse.get("name", "Unknown Pulse")
            pulse_id = pulse.get("id")
            # Factor 3: Internal source name for mapping
            feed_source = "alienvault_parser" 
            
            # 2. AlienVault Indicators are nested inside each Pulse
            indicators = pulse.get("indicators", [])
            
            for ind in indicators:
                indicator_val = ind.get("indicator")
                if not indicator_val:
                    continue

                # 3. Standardized Record for Deduplication
                record = {
                    # Factor 2: Align with the Deduplicator's search key
                    "value": indicator_val,           
                    "type": ind.get("type", "unknown").lower(),
                    "source": feed_source,             # Mapped to 'AlienVault OTX' by Deduplicator
                    
                    # Contextual Data from the Pulse
                    "title": pulse_name,
                    "description": pulse.get("description"),
                    "pulse_id": pulse_id,
                    "author": pulse.get("author_name"),
                    
                    # Technical Details
                    "severity": ind.get("role") or "medium", # OTX uses 'role' or pulse metadata
                    "confidence": 75,                         # Community data is slightly lower than CISA
                    "tags": list(set(pulse.get("tags", []) + ["alienvault", "otx", "osint"])),
                    
                    # Metadata
                    "first_seen": pulse.get("created"),
                    "last_modified": pulse.get("modified"),
                }

                items.append(record)

        logger.info(f"Parsed {len(items)} total indicators from AlienVault OTX pulses.")
        return items
