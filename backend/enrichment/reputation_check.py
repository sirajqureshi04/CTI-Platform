"""
Reputation checking for IOCs.
Integrates with external Threat Intel APIs and provides unified scoring.
"""

import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional

from backend.core.logger import CTILogger
from backend.core.config import settings

logger = CTILogger.get_logger(__name__)

class ReputationChecker:
    """
    Checks IOC reputation against VirusTotal, AbuseIPDB, and other sources.
    Uses a hash-based cache to prevent redundant API billing costs.
    """
    
    def __init__(self, cache_dir: Optional[Path] = None):
        if cache_dir is None:
            self.cache_dir = Path(settings.BASE_DIR) / "cache" / "enrichment" / "reputation"
        else:
            self.cache_dir = Path(cache_dir)
            
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # API Keys from centralized settings
        self.vt_api_key = getattr(settings, "VIRUSTOTAL_API_KEY", None)
        self.abuse_api_key = getattr(settings, "ABUSEIPDB_API_KEY", None)
        
        logger.info("Reputation Checker initialized with multi-source support.")

    def check(self, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
        """
        Main entry point for EnrichmentManager.
        Standardizes 'type' to match the database expectations.
        """
        # Normalize type (e.g., ipv4 -> ip)
        normalized_type = "ip" if ioc_type in ["ipv4", "ipv6"] else ioc_type
        
        # Check cache
        cached = self._load_cache(normalized_type, ioc_value)
        if cached:
            # Check if cache is older than 24 hours (CTI data goes stale fast)
            last_check = datetime.fromisoformat(cached["check_timestamp"])
            if (datetime.utcnow() - last_check).days < 1:
                return cached
        
        # Perform live check
        reputation = self._perform_check(normalized_type, ioc_value)
        self._save_cache(normalized_type, ioc_value, reputation)
        
        return reputation

    def _perform_check(self, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
        """Coordinates multiple API calls and aggregates scores."""
        results = []
        
        # 1. Logic for VirusTotal (IP, Domain, Hash)
        if self.vt_api_key:
            vt_res = self._query_virustotal(ioc_type, ioc_value)
            if vt_res: results.append(vt_res)
            
        # 2. Logic for AbuseIPDB (IP only)
        if ioc_type == "ip" and self.abuse_api_key:
            abuse_res = self._query_abuseipdb(ioc_value)
            if abuse_res: results.append(abuse_res)

        # 3. Aggregate results
        return self._calculate_final_score(ioc_type, ioc_value, results)

    def _query_virustotal(self, ioc_type: str, ioc_value: str) -> Optional[Dict]:
        """Placeholder for VirusTotal API Integration."""
        # In production: requests.get(f"https://www.virustotal.com/api/v3/...")
        return {"provider": "VirusTotal", "malicious_votes": 0, "harmless_votes": 20}

    def _query_abuseipdb(self, ip: str) -> Optional[Dict]:
        """Placeholder for AbuseIPDB API Integration."""
        # In production: requests.get(f"https://api.abuseipdb.com/api/v2/check...")
        return {"provider": "AbuseIPDB", "abuse_score": 0}

    def _calculate_final_score(self, ioc_type: str, ioc_value: str, provider_data: List[Dict]) -> Dict[str, Any]:
        """Determines the final threat level based on provider consensus."""
        
        # Default State
        threat_level = "clear"
        score = 0
        
        # Logic: If any major provider flags it, escalate threat level
        for data in provider_data:
            if data.get("malicious_votes", 0) > 3 or data.get("abuse_score", 0) > 50:
                threat_level = "malicious"
                score = 100

        return {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "reputation_score": score,
            "threat_level": threat_level,
            "is_malicious": threat_level == "malicious",
            "providers": provider_data,
            "check_timestamp": datetime.utcnow().isoformat()
        }

    # --- Cache Management ---

    def _get_cache_key(self, ioc_type: str, ioc_value: str) -> str:
        return hashlib.sha256(f"{ioc_type}:{ioc_value}".encode()).hexdigest()

    def _load_cache(self, ioc_type: str, ioc_value: str) -> Optional[Dict]:
        path = self.cache_dir / f"{self._get_cache_key(ioc_type, ioc_value)}.json"
        if path.exists():
            try:
                with open(path, "r") as f: return json.load(f)
            except: return None
        return None

    def _save_cache(self, ioc_type: str, ioc_value: str, data: Dict):
        path = self.cache_dir / f"{self._get_cache_key(ioc_type, ioc_value)}.json"
        with open(path, "w") as f: json.dump(data, f, indent=2)

