from typing import Any, Dict, List, Set

from backend.core.logger import CTILogger
from backend.parser.base_parser import BaseParser

logger = CTILogger.get_logger(__name__)


class RansomwareParser(BaseParser):
    """
    Parser for ransomware-focused feeds (e.g., ransomware.live victims).
    Converts raw feed structures into normalized IOC-style records.
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            name="ransomware_parser",
            config=config or {}
        )

    def parse(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parse ransomware feed data into a flat list of normalized items.

        Current support:
        - source == "ransomware.live": expects raw_data["data"]["victims"] as a list of dicts.
        """
        source = raw_data.get("source", "unknown")
        items: List[Dict[str, Any]] = []

        if source == "ransomware.live":
            victims = raw_data.get("data", {}).get("victims", [])
            for v in victims:
                name = v.get("name") or v.get("victim") or str(v.get("id", "unknown"))
                metadata = {
                    "group": v.get("group") or v.get("group_name"),
                    "discovered": v.get("discovered") or v.get("discovered_at"),
                    "published": v.get("published"),
                    "raw": v,
                }
                items.append(
                    self.normalize_ioc(
                        ioc_type="ransomware_victim",
                        ioc_value=name,
                        metadata=metadata,
                    )
                )
        else:
            logger.warning(f"Unsupported source for RansomwareParser: {source}")

        return items

    def extract_iocs(self, parsed_data: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
        """
        Group normalized items by IOC type, using sets for deduplication.
        """
        iocs_by_type: Dict[str, Set[str]] = {}

        for ioc in parsed_data:
            itype = ioc["ioc_type"]
            ivalue = ioc["ioc_value"]

            if itype not in iocs_by_type:
                iocs_by_type[itype] = set()

            iocs_by_type[itype].add(ivalue)

        return iocs_by_type
