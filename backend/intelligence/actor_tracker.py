"""
Threat actor tracking module.

Tracks threat actor activity, associations, and IOCs across
multiple feeds and time periods.
"""

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)


class ActorTracker:
    """
    Tracks threat actors and their associated IOCs.
    
    Maintains actor profiles, IOC associations, and activity timelines.
    """
    
    def __init__(self, data_dir: Path = None):
        """
        Initialize actor tracker.
        
        Args:
            data_dir: Directory for storing actor data
        """
        if data_dir is None:
            data_dir = Path(__file__).parent.parent.parent / "data" / "processed"
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self._actors: Dict[str, Dict[str, Any]] = {}
        self._load_actors()
        
        logger.info(f"Initialized actor tracker with {len(self._actors)} actors")
    
    def _load_actors(self) -> None:
        """Load actor data from disk and normalize in-memory types."""
        actors_file = self.data_dir / "actors.json"
        if actors_file.exists():
            try:
                with open(actors_file, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                # Normalize sources to sets in memory
                self._actors = {}
                for name, actor in loaded.items():
                    sources = actor.get("sources") or []
                    if isinstance(sources, list):
                        actor["sources"] = set(sources)
                    elif isinstance(sources, set):
                        actor["sources"] = sources
                    else:
                        actor["sources"] = set()
                    self._actors[name] = actor
            except Exception as e:
                logger.warning(f"Failed to load actors: {e}")
                self._actors = {}
    
    def _save_actors(self) -> None:
        """Save actor data to disk (converting sets to lists)."""
        actors_file = self.data_dir / "actors.json"
        try:
            serializable: Dict[str, Dict[str, Any]] = {}
            for name, actor in self._actors.items():
                data = dict(actor)
                sources = data.get("sources")
                if isinstance(sources, set):
                    data["sources"] = list(sources)
                serializable[name] = data

            with open(actors_file, "w", encoding="utf-8") as f:
                json.dump(serializable, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save actors: {e}")
    
    def track_actor(self, actor_name: str, ioc: Dict[str, Any]) -> None:
        """
        Associate an IOC with a threat actor.
        
        Args:
            actor_name: Threat actor name/identifier
            ioc: IOC dictionary
        """
        if actor_name not in self._actors:
            self._actors[actor_name] = {
                "name": actor_name,
                "iocs": [],
                "first_seen": ioc.get("first_seen"),
                "last_seen": ioc.get("last_seen"),
                "ioc_count": 0,
                "sources": set()
            }
        
        actor = self._actors[actor_name]
        actor["iocs"].append(ioc)
        actor["ioc_count"] = len(actor["iocs"])
        actor["last_seen"] = ioc.get("last_seen")
        actor["sources"].add(ioc.get("source", "unknown"))
        
        self._save_actors()
    
    def get_actor(self, actor_name: str) -> Dict[str, Any]:
        """
        Get actor information.
        
        Args:
            actor_name: Threat actor name
            
        Returns:
            Actor dictionary or empty dict if not found
        """
        return self._actors.get(actor_name, {})
    
    def get_all_actors(self) -> List[Dict[str, Any]]:
        """
        Get all tracked actors.
        
        Returns:
            List of actor dictionaries
        """
        return list(self._actors.values())
    
    def extract_actors_from_iocs(self, iocs: List[Dict[str, Any]]) -> None:
        """
        Extract and track actors from IOC metadata.
        
        Args:
            iocs: List of IOC dictionaries
        """
        for ioc in iocs:
            metadata = ioc.get("metadata", {})
            actor_name = metadata.get("group") or metadata.get("threat_actor") or metadata.get("actor")
            
            if actor_name:
                self.track_actor(actor_name, ioc)
        
        logger.info(f"Extracted actors from {len(iocs)} IOCs")

