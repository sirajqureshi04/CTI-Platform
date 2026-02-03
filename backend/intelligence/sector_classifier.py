"""
Sector classification module.

Classifies IOCs and threats by industry sector for
UAE-specific threat intelligence.
"""

from typing import Any, Dict, List

from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)


class SectorClassifier:
    """
    Classifies IOCs and threats by industry sector.
    
    Provides UAE-specific sector classification for threat
    intelligence prioritization.
    """
    
    # Sector keywords and patterns
    SECTOR_PATTERNS = {
        "government": [
            "government", "ministry", "federal", "municipality",
            "authority", "department", "agency", "public sector"
        ],
        "finance": [
            "bank", "financial", "investment", "insurance",
            "credit", "payment", "fintech", "trading"
        ],
        "energy": [
            "oil", "gas", "petroleum", "energy", "power",
            "electricity", "utilities", "refinery"
        ],
        "healthcare": [
            "hospital", "medical", "health", "clinic",
            "pharmacy", "healthcare", "biotech"
        ],
        "aviation": [
            "airline", "airport", "aviation", "aircraft",
            "aerospace", "cargo"
        ],
        "tourism": [
            "hotel", "tourism", "travel", "resort",
            "hospitality", "leisure"
        ],
        "retail": [
            "retail", "mall", "shopping", "store",
            "supermarket", "ecommerce"
        ],
        "technology": [
            "tech", "software", "it", "telecom",
            "communications", "internet", "cloud"
        ],
        "education": [
            "university", "school", "education", "academic",
            "research", "institute"
        ],
        "real_estate": [
            "real estate", "property", "construction",
            "development", "housing"
        ]
    }
    
    def __init__(self):
        """Initialize sector classifier."""
        logger.info("Initialized sector classifier")
    
    def classify(self, ioc: Dict[str, Any]) -> List[str]:
        """
        Classify an IOC by sector.
        
        Args:
            ioc: IOC dictionary
            
        Returns:
            List of sector classifications
        """
        sectors = []
        metadata = ioc.get("metadata", {})
        
        # Combine all text fields for analysis
        text_fields = [
            str(ioc.get("ioc_value", "")),
            str(metadata.get("victim_name", "")),
            str(metadata.get("product", "")),
            str(metadata.get("vendor_project", "")),
            str(metadata.get("description", ""))
        ]
        
        combined_text = " ".join(text_fields).lower()
        
        # Match against sector patterns
        for sector, patterns in self.SECTOR_PATTERNS.items():
            for pattern in patterns:
                if pattern in combined_text:
                    if sector not in sectors:
                        sectors.append(sector)
                    break
        
        return sectors
    
    def classify_batch(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Classify a batch of IOCs by sector.
        
        Args:
            iocs: List of IOC dictionaries
            
        Returns:
            List of IOCs with sector classifications added
        """
        classified = []
        for ioc in iocs:
            sectors = self.classify(ioc)
            ioc["sectors"] = sectors
            classified.append(ioc)
        
        logger.info(f"Classified {len(classified)} IOCs by sector")
        return classified
    
    def get_sector_statistics(self, iocs: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Get sector distribution statistics.
        
        Args:
            iocs: List of IOC dictionaries
            
        Returns:
            Dictionary mapping sectors to counts
        """
        sector_counts = {}
        for ioc in iocs:
            sectors = ioc.get("sectors", [])
            for sector in sectors:
                sector_counts[sector] = sector_counts.get(sector, 0) + 1
        
        return sector_counts

