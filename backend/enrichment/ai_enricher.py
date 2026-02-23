"""
AI-powered enrichment for CTI data.
Refined for: storage/final/ post-processing and tiered analysis.
"""

from datetime import datetime
from typing import Any, Dict, Optional
import json

from backend.core.logger import CTILogger
from backend.core.config import settings

# If you decide to use OpenAI or Anthropic later:
# import openai 

logger = CTILogger.get_logger(__name__)

class AIEnricher:
    def __init__(self):
        self.api_key = getattr(settings, "OPENAI_API_KEY", None)
        self.enabled = bool(self.api_key)
        
        if not self.enabled:
            logger.warning("AI Enricher running in MOCK MODE: No API Key found.")
        else:
            logger.info("AI Enricher initialized for Production.")

    def enrich(self, indicator: Dict[str, Any]) -> Dict[str, Any]:
        """
        Refined Entry Point: Processes a single indicator dictionary 
        after it has been pulled from final storage.
        """
        # We don't return the whole data object anymore, just the AI portion
        # to be merged by the manager.
        analysis = {}

        # Logic Gate 1: Strategic Analysis (Ransomware/Victims)
        if indicator.get("type") == "victim" or "victim_name" in indicator:
            analysis = self._analyze_ransomware_event(indicator)
        
        # Logic Gate 2: Technical Attribution (IP/Domain/CVE)
        elif indicator.get("value"):
            analysis = self._classify_indicator(indicator)

        return analysis

    def _analyze_ransomware_event(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Summarizes leak data. 
        Refinement: Now accepts the full indicator to 'read' the description.
        """
        description = data.get("description", "")
        group = data.get("source_label", "Unknown Group") # Uses our new mapping labels

        # Refined Logic: If description is short, don't waste API credits.
        if len(description) < 50:
            return {"note": "Description too short for meaningful AI analysis."}

        # Placeholder for LLM Call
        return {
            "summary": f"Strategic summary of {group} activity...",
            "threat_level": "Elevated",
            "detected_ttps": ["Data Exfiltration", "Inhibition of System Recovery"],
            "generated_at": datetime.utcnow().isoformat()
        }

    def _classify_indicator(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Refinement: This now looks at EXISTING enrichment (like GeoIP) 
        to provide a 'Fused' analysis.
        """
        ioc_value = ioc.get("value")
        geo_data = ioc.get("enrichment", {}).get("geo", {})
        
        # The AI 'sees' that the IP is in a specific country and was reported by AlienVault
        context = f"IOC {ioc_value} located in {geo_data.get('country', 'Unknown')}"

        return {
            "verdict": "Malicious",
            "context": f"AI analysis based on: {context}",
            "attribution": "Likely Crimeware",
            "confidence_score": 0.82
        }    