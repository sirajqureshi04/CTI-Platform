import re
from typing import Any, Dict, List, Set
from backend.core.logger import CTILogger
from backend.parser.base_parser import BaseParser

logger = CTILogger.get_logger(__name__)

def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    return re.findall(r'https?://\S+', text)

def normalize_severity(text: str) -> str:
    if not text:
        return "high" # KEVs are exploited, default to high
    t = text.lower()
    if any(kw in t for kw in ["remote code execution", "rce", "critical"]):
        return "critical"
    if any(kw in t for kw in ["code injection", "privilege escalation", "high"]):
        return "high"
    return "high"

class CISAKEVParser(BaseParser):
    """
    CTI-grade parser for CISA Known Exploited Vulnerabilities.
    Implements extract_iocs to fix the TypeError.
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            # name matches your test_parser mapping
            name="cisa_kev",  
            config=config or {}
        )

    def parse(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        items = []

        # Your feed saves data as {"vulnerabilities": [...]} inside the 'data' wrapper
        # We access it directly from the payload passed by test_parser_storage
        vulnerabilities = raw_data.get("vulnerabilities", [])

        for v in vulnerabilities:
            cve_id = v.get("cveID")
            if not cve_id:
                continue

            # Contextual Data
            metadata = {
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "title": v.get("vulnerabilityName"),
                "description": v.get("shortDescription"),
                "cwe": v.get("cwes", []),
                "ransomware_used": v.get("knownRansomwareCampaignUse"),
                "first_seen": v.get("dateAdded"),
                "due_date": v.get("dueDate"),
                "references": extract_urls(v.get("notes", "")),
                "severity": normalize_severity(v.get("shortDescription")),
                "confidence": 95,
                "tags": ["cisa", "kev", "vulnerability", "exploited"]
            }

            # Normalize into the unified format expected by to_processed_indicators
            # This ensures keys like 'ioc_type' and 'ioc_value' exist
            record = self.normalize_ioc(
                ioc_type="cve",
                ioc_value=cve_id.upper(),
                metadata=metadata
            )

            items.append(record)

        logger.info(f"Parsed {len(items)} vulnerabilities from CISA KEV.")
        return items

    def extract_iocs(self, parsed_data: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
        """
        FIXES THE TYPEERROR.
        Groups unique CVEs for the summary report.
        """
        iocs = {"cve": set()}
        for item in parsed_data:
            val = item.get("ioc_value")
            if val:
                iocs["cve"].add(val)
        return iocs