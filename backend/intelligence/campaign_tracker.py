"""
Campaign tracking module.

Tracks threat campaigns, their IOCs, and temporal patterns
across multiple feeds and sources.
"""

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)


class CampaignTracker:
    """
    Tracks threat campaigns and their associated IOCs.
    
    Identifies campaigns based on temporal patterns, actor associations,
    and IOC clustering.
    """
    
    def __init__(self, data_dir: Path = None):
        """
        Initialize campaign tracker.
        
        Args:
            data_dir: Directory for storing campaign data
        """
        if data_dir is None:
            data_dir = Path(__file__).parent.parent.parent / "data" / "processed"
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self._campaigns: Dict[str, Dict[str, Any]] = {}
        self._load_campaigns()
        
        logger.info(f"Initialized campaign tracker with {len(self._campaigns)} campaigns")
    
    def _load_campaigns(self) -> None:
        """Load campaign data from disk and normalize in-memory types."""
        campaigns_file = self.data_dir / "campaigns.json"
        if campaigns_file.exists():
            try:
                with open(campaigns_file, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                self._campaigns = {}
                for cid, campaign in loaded.items():
                    sources = campaign.get("sources") or []
                    actors = campaign.get("actors") or []
                    if isinstance(sources, list):
                        campaign["sources"] = set(sources)
                    elif isinstance(sources, set):
                        campaign["sources"] = sources
                    else:
                        campaign["sources"] = set()
                    if isinstance(actors, list):
                        campaign["actors"] = set(actors)
                    elif isinstance(actors, set):
                        campaign["actors"] = actors
                    else:
                        campaign["actors"] = set()
                    self._campaigns[cid] = campaign
            except Exception as e:
                logger.warning(f"Failed to load campaigns: {e}")
                self._campaigns = {}
    
    def _save_campaigns(self) -> None:
        """Save campaign data to disk (converting sets to lists)."""
        campaigns_file = self.data_dir / "campaigns.json"
        try:
            serializable: Dict[str, Dict[str, Any]] = {}
            for cid, campaign in self._campaigns.items():
                data = dict(campaign)
                sources = data.get("sources")
                actors = data.get("actors")
                if isinstance(sources, set):
                    data["sources"] = list(sources)
                if isinstance(actors, set):
                    data["actors"] = list(actors)
                serializable[cid] = data

            with open(campaigns_file, "w", encoding="utf-8") as f:
                json.dump(serializable, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save campaigns: {e}")
    
    def identify_campaign(self, ioc: Dict[str, Any]) -> str:
        """
        Identify campaign for an IOC.
        
        Args:
            ioc: IOC dictionary
            
        Returns:
            Campaign identifier
        """
        metadata = ioc.get("metadata", {})
        
        # Check for explicit campaign identifier
        campaign_id = metadata.get("campaign_id") or metadata.get("campaign")
        
        if campaign_id:
            return campaign_id
        
        # Cluster by actor and time window
        actor = metadata.get("group") or metadata.get("threat_actor")
        first_seen = ioc.get("first_seen", "")
        
        if actor and first_seen:
            # Generate campaign ID from actor and date
            date_part = first_seen[:10] if len(first_seen) >= 10 else "unknown"
            campaign_id = f"{actor}_{date_part}"
            return campaign_id
        
        return "unknown"
    
    def track_campaign(self, campaign_id: str, ioc: Dict[str, Any]) -> None:
        """
        Associate an IOC with a campaign.
        
        Args:
            campaign_id: Campaign identifier
            ioc: IOC dictionary
        """
        if campaign_id not in self._campaigns:
            self._campaigns[campaign_id] = {
                "campaign_id": campaign_id,
                "iocs": [],
                "first_seen": ioc.get("first_seen"),
                "last_seen": ioc.get("last_seen"),
                "ioc_count": 0,
                "sources": set(),
                "actors": set()
            }
        
        campaign = self._campaigns[campaign_id]
        campaign["iocs"].append(ioc)
        campaign["ioc_count"] = len(campaign["iocs"])
        campaign["last_seen"] = ioc.get("last_seen")
        campaign["sources"].add(ioc.get("source", "unknown"))
        
        # Extract actor from metadata
        metadata = ioc.get("metadata", {})
        actor = metadata.get("group") or metadata.get("threat_actor")
        if actor:
            campaign["actors"].add(actor)
        
        # Convert sets to lists for JSON serialization
        campaign["sources"] = list(campaign["sources"])
        campaign["actors"] = list(campaign["actors"])
        
        self._save_campaigns()
    
    def get_campaign(self, campaign_id: str) -> Dict[str, Any]:
        """
        Get campaign information.
        
        Args:
            campaign_id: Campaign identifier
            
        Returns:
            Campaign dictionary or empty dict if not found
        """
        return self._campaigns.get(campaign_id, {})
    
    def get_all_campaigns(self) -> List[Dict[str, Any]]:
        """
        Get all tracked campaigns.
        
        Returns:
            List of campaign dictionaries
        """
        return list(self._campaigns.values())
    
    def process_iocs(self, iocs: List[Dict[str, Any]]) -> None:
        """
        Process IOCs and assign to campaigns.
        
        Args:
            iocs: List of IOC dictionaries
        """
        for ioc in iocs:
            campaign_id = self.identify_campaign(ioc)
            self.track_campaign(campaign_id, ioc)
        
        logger.info(f"Processed {len(iocs)} IOCs into campaigns")

