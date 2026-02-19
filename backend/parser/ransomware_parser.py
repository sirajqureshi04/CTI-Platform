from typing import Any, Dict, List, Set
import re
from datetime import datetime

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
            name="ransomware_parser",
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
        name = re.sub(r"[^a-z0-9_\\-\\.]", "", name)
        return name

    def _parse_timestamp(self, ts: Any) -> str | None:
        if not ts:
            return None
        try:
            if isinstance(ts, (int, float)):
                return datetime.utcfromtimestamp(ts).isoformat() + "Z"
            if isinstance(ts, str):
                return datetime.fromisoformat(ts.replace("Z", "")).isoformat() + "Z"
        except Exception:
            return None
        return None

    # ----------------------------
    # Core Parser
    # ----------------------------

    def parse(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        source = raw_data.get("source", "unknown")
        items: List[Dict[str, Any]] = []

        if source != "ransomware.live":
            logger.warning(f"Unsupported source for RansomwareParser: {source}")
            return items

        victims = raw_data.get("data", {}).get("victims")

        if not isinstance(victims, list):
            logger.error("ransomware.live payload missing 'victims' list")
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

            # Stable identity
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
                "source": "ransomware.live",
                "raw_id": v.get("id"),
            }

            items.append(
                self.normalize_ioc(
                    ioc_type="ransomware_victim",
                    ioc_value=ioc_value,
                    metadata=metadata,
                )
            )

        logger.info(f"Parsed {len(items)} ransomware victims from ransomware.live")
        return items

    # ----------------------------
    # IOC Extraction
    # ----------------------------

    def extract_iocs(self, parsed_data: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
        """
        Group normalized items by IOC type, using sets for deduplication.
        Defensive against malformed records.
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
