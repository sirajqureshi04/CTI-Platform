"""
STIX exporter for threat intelligence.

Exports IOCs and threat intelligence in STIX 2.1 format
for integration with security tools and platforms.
"""

import json
from datetime import datetime
from typing import Any, Dict, List
from uuid import uuid4

from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)


class STIXExporter:
    """
    Exports threat intelligence in STIX 2.1 format.
    
    Converts IOCs and threat intelligence into STIX objects
    for sharing and integration.
    """
    
    def __init__(self):
        """Initialize STIX exporter."""
        logger.info("Initialized STIX exporter")
    
    def export_iocs(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Export IOCs as STIX bundle.
        
        Args:
            iocs: List of IOC dictionaries
            
        Returns:
            STIX bundle dictionary
        """
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid4()}",
            "spec_version": "2.1",
            "objects": []
        }
        
        for ioc in iocs:
            stix_object = self._ioc_to_stix(ioc)
            if stix_object:
                bundle["objects"].append(stix_object)
        
        logger.info(f"Exported {len(bundle['objects'])} IOCs as STIX bundle")
        return bundle
    
    def _ioc_to_stix(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert IOC to STIX object.
        
        Args:
            ioc: IOC dictionary
            
        Returns:
            STIX object dictionary
        """
        ioc_type = ioc.get("ioc_type", "").lower()
        ioc_value = ioc.get("ioc_value", "")
        
        if not ioc_value:
            return None
        
        # Map IOC types to STIX indicator patterns
        pattern_mapping = {
            "ip": f"[ipv4-addr:value = '{ioc_value}']",
            "domain": f"[domain-name:value = '{ioc_value}']",
            "url": f"[url:value = '{ioc_value}']",
            "hash": self._hash_to_stix_pattern(ioc_value, ioc),
            "cve": f"[vulnerability:name = '{ioc_value}']",
            "email": f"[email-addr:value = '{ioc_value}']"
        }
        
        pattern = pattern_mapping.get(ioc_type)
        if not pattern:
            # Default pattern
            pattern = f"[{ioc_type}:value = '{ioc_value}']"
        
        # Create STIX indicator
        stix_indicator = {
            "type": "indicator",
            "id": f"indicator--{uuid4()}",
            "spec_version": "2.1",
            "created": ioc.get("first_seen", datetime.now().isoformat()),
            "modified": ioc.get("last_seen", datetime.now().isoformat()),
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": ioc.get("first_seen", datetime.now().isoformat()),
            "labels": ["malicious-activity"],
            "confidence": self._calculate_confidence(ioc)
        }
        
        # Add kill chain phases if available
        metadata = ioc.get("metadata", {})
        if metadata.get("threat_level") or metadata.get("risk_level"):
            stix_indicator["kill_chain_phases"] = [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "initial-access"
                }
            ]
        
        return stix_indicator
    
    def _hash_to_stix_pattern(self, hash_value: str, ioc: Dict[str, Any]) -> str:
        """Convert hash to STIX pattern."""
        hash_length = len(hash_value)
        if hash_length == 32:
            return f"[file:hashes.'MD5' = '{hash_value}']"
        elif hash_length == 40:
            return f"[file:hashes.'SHA-1' = '{hash_value}']"
        elif hash_length == 64:
            return f"[file:hashes.'SHA-256' = '{hash_value}']"
        else:
            return f"[file:hashes.'UNKNOWN' = '{hash_value}']"
    
    def _calculate_confidence(self, ioc: Dict[str, Any]) -> int:
        """Calculate STIX confidence score (0-100)."""
        risk_score = ioc.get("risk_score", 0)
        relevance_score = ioc.get("relevance_score", 0)
        
        # Combine risk and relevance scores
        confidence = int((risk_score + (relevance_score * 100)) / 2)
        return min(max(confidence, 0), 100)
    
    def export_to_file(self, iocs: List[Dict[str, Any]], filepath: str) -> None:
        """
        Export IOCs to STIX file.
        
        Args:
            iocs: List of IOC dictionaries
            filepath: Output file path
        """
        bundle = self.export_iocs(iocs)
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2, default=str)
        
        logger.info(f"Exported STIX bundle to {filepath}")

