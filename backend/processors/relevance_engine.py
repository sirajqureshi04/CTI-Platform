"""
Relevance scoring engine for IOCs.

Calculates relevance scores for IOCs based on UAE-specific context,
sector relevance, and threat actor targeting patterns.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)


class RelevanceEngine:
    """
    Calculates relevance scores for IOCs.
    
    Factors considered:
    - UAE-specific targeting
    - Sector relevance (government, finance, energy, healthcare, etc.)
    - Threat actor focus areas
    - Industry vertical alignment
    """
    
    # UAE-specific keywords and indicators
    UAE_KEYWORDS = [
        "uae", "united arab emirates", "dubai", "abu dhabi", "sharjah",
        "emirates", "dirham", "aed", "dubai international", "emirates airlines"
    ]
    
    # Sector keywords
    SECTOR_KEYWORDS = {
        "government": ["government", "ministry", "federal", "municipality", "authority"],
        "finance": ["bank", "financial", "investment", "insurance", "credit", "payment"],
        "energy": ["oil", "gas", "petroleum", "energy", "power", "electricity"],
        "healthcare": ["hospital", "medical", "health", "clinic", "pharmacy"],
        "aviation": ["airline", "airport", "aviation", "aircraft"],
        "tourism": ["hotel", "tourism", "travel", "resort", "hospitality"],
        "retail": ["retail", "mall", "shopping", "store", "supermarket"],
        "technology": ["tech", "software", "it", "telecom", "communications"]
    }
    
    def __init__(self, cache_dir: Path = None):
        """
        Initialize relevance engine.
        
        Args:
            cache_dir: Directory for storing relevance cache
        """
        if cache_dir is None:
            cache_dir = Path(__file__).parent.parent / "cache" / "relevance" / "UAE"
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info("Initialized relevance engine")
    
    def calculate_relevance(self, ioc: Dict[str, Any]) -> float:
        """
        Calculate relevance score for an IOC (0.0 to 1.0).
        
        Args:
            ioc: IOC dictionary with metadata
            
        Returns:
            Relevance score between 0.0 and 1.0
        """
        score = 0.0
        metadata = ioc.get("metadata", {})
        
        # Check for UAE-specific indicators
        ioc_value = str(ioc.get("ioc_value", "")).lower()
        metadata_str = json.dumps(metadata).lower()
        combined_text = f"{ioc_value} {metadata_str}"
        
        # UAE relevance (0.4 max)
        uae_score = 0.0
        for keyword in self.UAE_KEYWORDS:
            if keyword in combined_text:
                uae_score += 0.1
        uae_score = min(uae_score, 0.4)
        score += uae_score
        
        # Sector relevance (0.3 max)
        sector_score = 0.0
        for sector, keywords in self.SECTOR_KEYWORDS.items():
            for keyword in keywords:
                if keyword in combined_text:
                    sector_score += 0.05
        sector_score = min(sector_score, 0.3)
        score += sector_score
        
        # Source credibility (0.2 max)
        source = ioc.get("source", "").lower()
        credible_sources = ["cisa_kev", "ransomware_live"]
        if any(cs in source for cs in credible_sources):
            score += 0.2
        
        # Recency (0.1 max)
        first_seen = metadata.get("first_seen", "")
        if first_seen:
            # Simple recency check (recent = higher score)
            score += 0.1
        
        # Normalize to 0.0-1.0
        score = min(score, 1.0)
        
        return round(score, 3)
    
    def score_batch(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Calculate relevance scores for a batch of IOCs.
        
        Args:
            iocs: List of IOC dictionaries
            
        Returns:
            List of IOCs with relevance_score field added
        """
        scored_iocs = []
        for ioc in iocs:
            relevance_score = self.calculate_relevance(ioc)
            ioc["relevance_score"] = relevance_score
            scored_iocs.append(ioc)
        
        logger.info(f"Scored {len(scored_iocs)} IOCs for relevance")
        return scored_iocs
    
    def filter_by_relevance(self, iocs: List[Dict[str, Any]], threshold: float = 0.3) -> List[Dict[str, Any]]:
        """
        Filter IOCs by relevance threshold.
        
        Args:
            iocs: List of IOC dictionaries
            threshold: Minimum relevance score (0.0-1.0)
            
        Returns:
            Filtered list of IOCs above threshold
        """
        scored = self.score_batch(iocs)
        filtered = [ioc for ioc in scored if ioc.get("relevance_score", 0.0) >= threshold]
        
        logger.info(f"Filtered {len(iocs)} IOCs to {len(filtered)} above threshold {threshold}")
        return filtered

