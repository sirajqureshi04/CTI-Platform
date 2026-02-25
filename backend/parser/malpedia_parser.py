import logging
from typing import Any, Dict, List, Set
from backend.core.logger import CTILogger
from backend.parser.base_parser import BaseParser

logger = CTILogger.get_logger(__name__)

class MalpediaParser(BaseParser):
    """
    Optimized parser for Malpedia data.
    Implements extract_iocs to satisfy BaseParser requirements.
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            name="malpedia",
            config=config or {}
        )

    def parse(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses Malpedia family data. 
        Adjusted to match the payload structure from the feed storage.
        """
        normalized_items = []
        
        # Your test_parser extracts 'data' from the raw file wrapper.
        # This payload usually contains the 'families' list directly.
        families = raw_data.get("families", [])
        
        # Fallback for different API response versions
        if not families and isinstance(raw_data, dict):
            families = raw_data.get("values", [])

        for entry in families:
            family_name = entry.get("value")
            if not family_name:
                continue

            meta = entry.get("meta", {})
            
            # 1. Normalize the Malware Family
            family_metadata = {
                "synonyms": meta.get("synonyms", []),
                "description": entry.get("description", ""),
                "attribution": meta.get("attribution", []),
                "type": meta.get("type", "malware_family"),
                "severity": "high",
                "confidence": 90,
                "tags": ["malpedia", "malware"]
            }
            
            normalized_items.append(
                self.normalize_ioc(
                    ioc_type="malware_family",
                    ioc_value=family_name,
                    metadata=family_metadata
                )
            )

            # 2. Extract External References as secondary IOCs (URLs)
            for ref in meta.get("refs", []):
                normalized_items.append(
                    self.normalize_ioc(
                        ioc_type="url",
                        ioc_value=ref,
                        metadata={
                            "malware_family": family_name, 
                            "context": "reference_link",
                            "severity": "low"
                        }
                    )
                )

        logger.info(f"Parsed {len(normalized_items)} items from Malpedia.")
        return normalized_items

    def extract_iocs(self, parsed_data: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
        """
        FIXES THE TYPEERROR.
        Groups IOCs by type and includes synonyms for better search coverage.
        """
        iocs_by_type: Dict[str, Set[str]] = {}

        for ioc in parsed_data:
            itype = ioc["ioc_type"]
            ivalue = ioc["ioc_value"]
            
            if itype not in iocs_by_type:
                iocs_by_type[itype] = set()
            
            iocs_by_type[itype].add(ivalue)
            
            # Index synonyms to make them searchable as family names
            if itype == "malware_family":
                for synonym in ioc.get("metadata", {}).get("synonyms", []):
                    iocs_by_type[itype].add(synonym)

        return iocs_by_type