"""
Diff engine for detecting changes in feed data.

Compares new feed data with previous versions to identify:
- New IOCs
- Updated IOCs
- Removed IOCs
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Set

from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)


class DiffEngine:
    """
    Detects differences between feed data versions.
    
    Compares current IOCs with previous versions to identify
    additions, updates, and removals.
    """
    
    def __init__(self, diff_dir: Path = None):
        """
        Initialize diff engine.
        
        Args:
            diff_dir: Directory for storing diff data
        """
        if diff_dir is None:
            diff_dir = Path(__file__).parent.parent.parent / "data" / "diff"
        self.diff_dir = Path(diff_dir)
        self.diff_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info("Initialized diff engine")
    
    def compare(
        self,
        current_iocs: List[Dict[str, Any]],
        previous_iocs: List[Dict[str, Any]],
        feed_name: str
    ) -> Dict[str, Any]:
        """
        Compare current IOCs with previous version.
        
        Args:
            current_iocs: Current list of IOCs
            previous_iocs: Previous list of IOCs
            feed_name: Name of the feed
            
        Returns:
            Dictionary with diff results
        """
        # Create sets of fingerprints for comparison
        current_fingerprints = {ioc.get("fingerprint") for ioc in current_iocs if ioc.get("fingerprint")}
        previous_fingerprints = {ioc.get("fingerprint") for ioc in previous_iocs if ioc.get("fingerprint")}
        
        # Find new, removed, and unchanged
        new_fingerprints = current_fingerprints - previous_fingerprints
        removed_fingerprints = previous_fingerprints - current_fingerprints
        unchanged_fingerprints = current_fingerprints & previous_fingerprints
        
        # Map fingerprints to IOCs
        current_map = {ioc.get("fingerprint"): ioc for ioc in current_iocs if ioc.get("fingerprint")}
        previous_map = {ioc.get("fingerprint"): ioc for ioc in previous_iocs if ioc.get("fingerprint")}
        
        new_iocs = [current_map[fp] for fp in new_fingerprints if fp in current_map]
        removed_iocs = [previous_map[fp] for fp in removed_fingerprints if fp in previous_map]
        
        # Check for updates (same fingerprint but different metadata)
        updated_iocs = []
        for fp in unchanged_fingerprints:
            if fp in current_map and fp in previous_map:
                current = current_map[fp]
                previous = previous_map[fp]
                if current != previous:
                    updated_iocs.append({
                        "fingerprint": fp,
                        "previous": previous,
                        "current": current
                    })
        
        diff_result = {
            "feed_name": feed_name,
            "timestamp": self._get_timestamp(),
            "new_count": len(new_iocs),
            "removed_count": len(removed_iocs),
            "updated_count": len(updated_iocs),
            "unchanged_count": len(unchanged_fingerprints) - len(updated_iocs),
            "new_iocs": new_iocs,
            "removed_iocs": removed_iocs,
            "updated_iocs": updated_iocs
        }
        
        # Save diff
        self._save_diff(diff_result, feed_name)
        
        logger.info(
            f"Diff for {feed_name}: {len(new_iocs)} new, {len(removed_iocs)} removed, "
            f"{len(updated_iocs)} updated"
        )
        
        return diff_result
    
    def _save_diff(self, diff_result: Dict[str, Any], feed_name: str) -> None:
        """Save diff result to disk."""
        timestamp = diff_result["timestamp"].replace(":", "-").replace(" ", "_")
        filename = f"{feed_name}_diff_{timestamp}.json"
        filepath = self.diff_dir / filename
        
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(diff_result, f, indent=2, default=str)
            logger.debug(f"Saved diff to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save diff: {e}")
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime
        return datetime.now().isoformat()

