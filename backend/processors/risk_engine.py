"""
Risk scoring engine for IOCs.

Calculates risk scores combining:
- Source credibility
- Exploitability
- Sector relevance
- Threat actor activity
"""

from typing import Any, Dict, List

from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)


class RiskEngine:
    """
    Calculates risk scores for IOCs.
    
    Risk factors:
    - Source credibility (0-30 points)
    - Exploitability (0-30 points)
    - Sector relevance (0-20 points)
    - Threat actor activity (0-20 points)
    """
    
    # Source credibility scores
    SOURCE_CREDIBILITY = {
        "cisa_kev": 30,
        "ransomware_live": 25,
        "alienvault_otx": 18,
        "malpedia": 15,
        "unknown": 5
    }
    
    # Exploitability indicators
    EXPLOITABILITY_FACTORS = {
        "cve": 30,  # Known exploited vulnerability
        "active_campaign": 25,
        "ransomware": 20,
        "botnet": 15,
        "malware": 10,
        "suspicious": 5
    }
    
    # Sector risk weights
    HIGH_RISK_SECTORS = ["government", "finance", "healthcare", "energy"]
    MEDIUM_RISK_SECTORS = ["aviation", "technology", "telecom"]
    
    def __init__(self):
        """Initialize risk engine."""
        logger.info("Initialized risk engine")
    
    def calculate_risk(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate comprehensive risk score for an IOC.
        
        Args:
            ioc: IOC dictionary with metadata
            
        Returns:
            Dictionary with risk score and breakdown
        """
        risk_score = 0.0
        breakdown = {}
        
        metadata = ioc.get("metadata", {})
        source = ioc.get("source", "unknown").lower()
        ioc_type = ioc.get("ioc_type", "").lower()
        
        # Source credibility (0-30)
        source_score = 0
        for cred_source, score in self.SOURCE_CREDIBILITY.items():
            if cred_source in source:
                source_score = score
                break
        if source_score == 0:
            source_score = self.SOURCE_CREDIBILITY["unknown"]
        
        breakdown["source_credibility"] = source_score
        risk_score += source_score
        
        # Exploitability (0-30)
        exploitability_score = 0
        
        # Check for CVE
        if ioc_type == "cve":
            exploitability_score = self.EXPLOITABILITY_FACTORS["cve"]
        
        # Check metadata for threat indicators
        metadata_str = str(metadata).lower()
        if "ransomware" in metadata_str or "ransom" in metadata_str:
            exploitability_score = max(exploitability_score, self.EXPLOITABILITY_FACTORS["ransomware"])
        if "campaign" in metadata_str or "active" in metadata_str:
            exploitability_score = max(exploitability_score, self.EXPLOITABILITY_FACTORS["active_campaign"])
        if "botnet" in metadata_str:
            exploitability_score = max(exploitability_score, self.EXPLOITABILITY_FACTORS["botnet"])
        if "malware" in metadata_str:
            exploitability_score = max(exploitability_score, self.EXPLOITABILITY_FACTORS["malware"])
        
        breakdown["exploitability"] = exploitability_score
        risk_score += exploitability_score
        
        # Sector relevance (0-20)
        sector_score = 0
        metadata_str = str(metadata).lower()
        for sector in self.HIGH_RISK_SECTORS:
            if sector in metadata_str:
                sector_score = 20
                break
        if sector_score == 0:
            for sector in self.MEDIUM_RISK_SECTORS:
                if sector in metadata_str:
                    sector_score = 10
                    break
        
        breakdown["sector_relevance"] = sector_score
        risk_score += sector_score
        
        # Threat actor activity (0-20)
        actor_score = 0
        if metadata.get("group") or metadata.get("threat_actor"):
            actor_score = 15
        if metadata.get("known_ransomware_campaign_use"):
            actor_score = 20
        
        breakdown["threat_actor_activity"] = actor_score
        risk_score += actor_score
        
        # Normalize to 0-100 scale
        risk_score = min(risk_score, 100.0)
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = "critical"
        elif risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 30:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "risk_score": round(risk_score, 2),
            "risk_level": risk_level,
            "breakdown": breakdown
        }
    
    def score_batch(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Calculate risk scores for a batch of IOCs.
        
        Args:
            iocs: List of IOC dictionaries
            
        Returns:
            List of IOCs with risk assessment added
        """
        scored_iocs = []
        for ioc in iocs:
            risk_assessment = self.calculate_risk(ioc)
            ioc["risk_score"] = risk_assessment["risk_score"]
            ioc["risk_level"] = risk_assessment["risk_level"]
            ioc["risk_breakdown"] = risk_assessment["breakdown"]
            scored_iocs.append(ioc)
        
        logger.info(f"Scored {len(scored_iocs)} IOCs for risk")
        return scored_iocs
    
    def filter_by_risk(self, iocs: List[Dict[str, Any]], min_level: str = "medium") -> List[Dict[str, Any]]:
        """
        Filter IOCs by minimum risk level.
        
        Args:
            iocs: List of IOC dictionaries
            min_level: Minimum risk level (low, medium, high, critical)
            
        Returns:
            Filtered list of IOCs above risk threshold
        """
        risk_levels = {"low": 0, "medium": 30, "high": 50, "critical": 70}
        min_score = risk_levels.get(min_level.lower(), 0)
        
        scored = self.score_batch(iocs)
        filtered = [ioc for ioc in scored if ioc.get("risk_score", 0) >= min_score]
        
        logger.info(f"Filtered {len(iocs)} IOCs to {len(filtered)} above risk level {min_level}")
        return filtered

