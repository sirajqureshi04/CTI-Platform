import re
from typing import Any, Dict, List, Set
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
            name="alienvault_otx", 
            config=config or {}
        )

    def parse(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        items = []
        
        # OTX raw data saved by your feed is usually: {"pulses": [...]}
        pulses = raw_data.get("pulses", [])
        
        # Fallback if the whole object is just a list
        if not pulses and isinstance(raw_data, list):
            pulses = raw_data

        for pulse in pulses:
            pulse_name = pulse.get("name", "Unknown Pulse")
            
            # Context shared by all indicators in this pulse
            metadata = {
                "title": pulse_name,
                "description": pulse.get("description"),
                "pulse_id": pulse.get("id"),
                "author": pulse.get("author_name"),
                "severity": "medium",
                "confidence": 75,
                "tags": list(set(pulse.get("tags", []) + ["alienvault", "otx"])),
                "first_seen": pulse.get("created"),
                "last_modified": pulse.get("modified"),
            }

            indicators = pulse.get("indicators", [])
            for ind in indicators:
                val = ind.get("indicator")
                itype = ind.get("type", "unknown")
                
                if val:
                    # Use base class normalization to ensure keys match test_parser.py
                    normalized = self.normalize_ioc(
                        ioc_type=itype,
                        ioc_value=val,
                        metadata=metadata
                    )
                    items.append(normalized)

        logger.info(f"Parsed {len(items)} indicators from OTX pulses.")
        return items

    def extract_iocs(self, parsed_data: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
        """
        Required implementation to satisfy BaseParser abstract method.
        Groups values by type for the summary metrics.
        """
        iocs = {}
        for item in parsed_data:
            itype = item["ioc_type"]
            ival = item["ioc_value"]
            if itype not in iocs:
                iocs[itype] = set()
            iocs[itype].add(ival)
        return iocs