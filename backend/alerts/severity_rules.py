"""
Severity rules for alerting.

Defines rules for determining alert severity based on IOC
risk scores, relevance, and threat characteristics.
"""

from typing import Any, Dict, List

from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)


class SeverityRules:
    """
    Severity rules engine for alerting.
    
    Determines alert severity based on IOC characteristics.
    """
    
    def __init__(self):
        """Initialize severity rules."""
        logger.info("Initialized severity rules")
    
    def determine_severity(self, ioc: Dict[str, Any]) -> str:
        """
        Determine alert severity for an IOC.
        
        Args:
            ioc: IOC dictionary
            
        Returns:
            Severity level (critical, high, medium, low)
        """
        risk_score = ioc.get("risk_score", 0)
        risk_level = ioc.get("risk_level", "low")
        relevance_score = ioc.get("relevance_score", 0)
        
        # Critical: High risk + high relevance
        if risk_score >= 70 and relevance_score >= 0.7:
            return "critical"
        
        # High: High risk OR high relevance
        if risk_score >= 50 or relevance_score >= 0.5:
            return "high"
        
        # Medium: Medium risk
        if risk_score >= 30 or risk_level == "medium":
            return "medium"
        
        # Low: Everything else
        return "low"
    
    def should_alert(self, ioc: Dict[str, Any], min_severity: str = "high") -> bool:
        """
        Determine if an alert should be sent for an IOC.
        
        Args:
            ioc: IOC dictionary
            min_severity: Minimum severity to trigger alert
            
        Returns:
            True if alert should be sent
        """
        severity = self.determine_severity(ioc)
        
        severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        min_level = severity_levels.get(min_severity.lower(), 2)
        current_level = severity_levels.get(severity.lower(), 0)
        
        return current_level >= min_level
    
    def filter_by_severity(self, iocs: List[Dict[str, Any]], min_severity: str = "high") -> List[Dict[str, Any]]:
        """
        Filter IOCs by minimum severity.
        
        Args:
            iocs: List of IOC dictionaries
            min_severity: Minimum severity level
            
        Returns:
            Filtered list of IOCs
        """
        filtered = [ioc for ioc in iocs if self.should_alert(ioc, min_severity)]
        logger.info(f"Filtered {len(iocs)} IOCs to {len(filtered)} above severity {min_severity}")
        return filtered

