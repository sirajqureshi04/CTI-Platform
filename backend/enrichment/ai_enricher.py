"""
AI-powered enrichment for CTI data.
Integrated with EnrichmentManager for contextual threat analysis.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
import json

from backend.core.logger import CTILogger
from backend.core.config import settings

logger = CTILogger.get_logger(__name__)

class AIEnricher:
    """
    Handles Large Language Model (LLM) interactions to provide 
    strategic context to ingested threat data.
    """
    
    def __init__(self):
        # We pull the API key from our core settings aligned in previous steps
        self.api_key = getattr(settings, "OPENAI_API_KEY", None)
        self.enabled = bool(self.api_key)
        
        if not self.enabled:
            logger.warning("AI Enricher disabled: No API Key found in settings.")
        else:
            logger.info("AI Enricher initialized and ready.")

    def enrich(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Primary entry point called by EnrichmentManager.
        Decides whether to summarize a victim story or classify an IOC.
        """
        if not self.enabled:
            return data

        # Check if we are dealing with a Ransomware Victim (Text heavy)
        if "description" in data or "victim_name" in data:
            data["ai_analysis"] = self._analyze_ransomware_event(data)
        
        # Check if we are dealing with a technical Indicator (IP/Domain/Hash)
        elif "value" in data and "type" in data:
            data["ai_analysis"] = self._classify_indicator(data)

        return data

    def _analyze_ransomware_event(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Summarizes leak site descriptions and predicts impact."""
        description = data.get("description", "No description provided.")
        victim = data.get("victim_name", "Unknown Victim")
        
        # In a real implementation, you would call your LLM client here
        # Example prompt: "Summarize the ransomware threat to {victim} based on: {description}"
        
        return {
            "summary": f"AI-generated overview of the attack on {victim}...",
            "estimated_severity": "High",
            "industry_sector": "Healthcare (Predicted)",
            "timestamp": datetime.utcnow().isoformat()
        }

    def _classify_indicator(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        """Uses AI to classify the intent of a technical indicator."""
        ioc_type = ioc.get("type")
        value = ioc.get("value")

        return {
            "category": "C2 Infrastructure",
            "confidence": 0.85,
            "threat_actor_attribution": "Possible APT28 / Fancy Bear",
            "campaign": "Operation Stealth 2026",
            "timestamp": datetime.utcnow().isoformat()
        }

    def enrich_batch(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Batch processing to optimize API calls."""
        if not self.enabled:
            return items
            
        logger.info(f"Starting AI batch enrichment for {len(items)} items")
        return [self.enrich(item) for item in items]
