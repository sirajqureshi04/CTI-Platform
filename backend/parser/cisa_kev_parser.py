import re
from typing import Any, Dict, List
from backend.core.logger import CTILogger
from backend.parser.base_parser import BaseParser

logger = CTILogger.get_logger(__name__)

def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    return re.findall(r'https?://\S+', text)

def normalize_severity(text: str) -> str:
    if not text:
        return "medium"
    t = text.lower()
    if any(kw in t for kw in ["remote code execution", "rce", "critical"]):
        return "critical"
    if any(kw in t for kw in ["code injection", "privilege escalation", "high"]):
        return "high"
    if "information disclosure" in t:
        return "medium"
    return "medium"

class CISAKEVParser(BaseParser):
    """
    CTI-grade parser for CISA Known Exploited Vulnerabilities.
    Refined to work with the multi-source Deduplicator.
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            name="cisa_parser",  # Internal name for mapping
            config=config or {}
        )

    def parse(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        items = []

        # Extract metadata from ingestion layer
        meta = raw_data.get("metadata", {})
        # FORCE source to 'cisa_parser' for the Deduplicator SOURCE_MAP
        feed_source = "cisa_parser" 
        ingested_at = meta.get("ingested_at")

        vulnerabilities = raw_data.get("data", {}).get("data", {}).get("vulnerabilities", [])

        for v in vulnerabilities:
            cve_id = v.get("cveID")
            if not cve_id:
                continue

            # Standardized Record for Deduplication
            record = {
                "value": cve_id.upper(),            # The unique ID used by Deduplicator
                "type": "cve",
                "source": feed_source,              # Used by Deduplicator to map to 'CISA KEV'
                
                # Contextual Data
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "title": v.get("vulnerabilityName"),
                "description": v.get("shortDescription"),

                # Technical Details
                "cwe": v.get("cwes", []),
                "ransomware_used": v.get("knownRansomwareCampaignUse"),
                "first_seen": v.get("dateAdded"),
                "due_date": v.get("dueDate"),
                "references": extract_urls(v.get("notes", "")),

                # System Metadata
                "ingested_at": ingested_at,
                "severity": normalize_severity(v.get("shortDescription")),
                "confidence": 95,                   # Higher confidence for official gov sources
                "tags": ["cisa", "kev", "vulnerability", "exploited"]
            }

            items.append(record)

        logger.info(f"Parsed {len(items)} vulnerabilities from CISA KEV.")
        return items