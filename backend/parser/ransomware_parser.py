from typing import Any, Dict, List, Set, Optional
import re
from datetime import datetime, timezone

from backend.core.logger import CTILogger
from backend.parser.base_parser import BaseParser

logger = CTILogger.get_logger(__name__)

class RansomwareParser(BaseParser):
    """
    Parser for ransomware-focused feeds (e.g., ransomware.live victims).
    Converts raw feed structures into normalized CTI IOC records.
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            name="ransomware",
            config=config or {}
        )

    # ----------------------------
    # Helpers
    # ----------------------------

    def _normalize_name(self, name: str) -> str:
        if not name:
            return "unknown"
        name = name.strip().lower()
        name = re.sub(r"\s+", "_", name)
        name = re.sub(r"[^a-z0-9_.\-]", "", name)
        return name

    def _parse_timestamp(self, ts: Any) -> Optional[str]:
        if not ts:
            return None
        try:
            if isinstance(ts, (int, float)):
                return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            if isinstance(ts, str):
                # Handle Z or offset-less strings
                return datetime.fromisoformat(ts.replace("Z", "+00:00")).isoformat()
        except Exception:
            return None
        return None

    # ----------------------------
    # Core Parser
    # ----------------------------

    def parse(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses the ransomware.live payload.
        Aligned with test_parser_storage extracting the 'data' key.
        """
        items: List[Dict[str, Any]] = []

        # The raw_data passed here is the 'data' object from the raw JSON file.
        # Based on your feed, it contains the 'victims' list directly.
        victims = raw_data.get("victims", [])

        if not victims and isinstance(raw_data, list):
            victims = raw_data

        if not victims:
            logger.warning("No victims found in Ransomware raw data.")
            return items

        for v in victims:
            if not isinstance(v, dict):
                continue

            raw_name = (
                v.get("name")
                or v.get("victim")
                or v.get("company")
                or "unknown"
            )

            group = v.get("group") or v.get("group_name") or "unknown"
            norm_name = self._normalize_name(raw_name)
            norm_group = self._normalize_name(group)

            # Stable identity for deduplication
            ioc_value = f"{norm_group}:{norm_name}"

            metadata = {
                "victim_name": raw_name,
                "group": group,
                "country": v.get("country"),
                "sector": v.get("sector") or v.get("industry"),
                "website": v.get("website") or v.get("domain"),
                "leak_url": v.get("url") or v.get("post_url"),
                "discovered_at": self._parse_timestamp(
                    v.get("discovered") or v.get("discovered_at")
                ),
                "published_at": self._parse_timestamp(v.get("published")),
                "severity": "high",
                "confidence": 85,
                "tags": ["ransomware", "leak_site", group.lower()]
            }

            items.append(
                self.normalize_ioc(
                    ioc_type="ransomware_victim",
                    ioc_value=ioc_value,
                    metadata=metadata,
                )
            )

        logger.info(f"Parsed {len(items)} ransomware victims.")
        return items

    # ----------------------------
    # IOC Extraction
    # ----------------------------

    def extract_iocs(self, parsed_data: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
        """
        Satisfies BaseParser requirement.
        Groups normalized items by IOC type.
        """
        iocs_by_type: Dict[str, Set[str]] = {}

        for ioc in parsed_data:
            itype = ioc.get("ioc_type")
            ivalue = ioc.get("ioc_value")

            if not itype or not ivalue:
                continue

            if itype not in iocs_by_type:
                iocs_by_type[itype] = set()

            iocs_by_type[itype].add(ivalue)

        return iocs_by_type