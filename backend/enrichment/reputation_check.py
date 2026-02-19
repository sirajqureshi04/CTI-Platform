import json
import hashlib
import requests
import time
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional

from backend.core.logger import CTILogger
from backend.core.config import settings

logger = CTILogger.get_logger(__name__)

class ReputationEnricher: # Renamed for Manager consistency
    """
    Checks IOC reputation against VirusTotal and AbuseIPDB.
    Optimized for Free Tier API constraints (Rate Limiting).
    """
    
    def __init__(self, cache_dir: Optional[Path] = None):
        base_path = getattr(settings, "BASE_DIR", ".")
        if cache_dir is None:
            self.cache_dir = Path(base_path) / "backend" / "cache" / "enrichment" / "reputation"
        else:
            self.cache_dir = Path(cache_dir)
            
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # API Keys
        self.vt_api_key = getattr(settings, "VIRUSTOTAL_API_KEY", None)
        self.abuse_api_key = getattr(settings, "ABUSEIPDB_API_KEY", None)

    def get_data(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point called by EnrichmentManager.
        Expects the full IOC dictionary.
        """
        ioc_type = ioc.get("type")
        ioc_value = ioc.get("value")
        
        # Normalize type for unified API handling
        normalized_type = "ip" if ioc_type in ["ipv4", "ipv6"] else ioc_type
        
        # 1. Check Cache (TTL: 24 Hours)
        cached = self._load_cache(normalized_type, ioc_value)
        if cached:
            last_check = datetime.fromisoformat(cached.get("check_timestamp", "2000-01-01"))
            if (datetime.utcnow() - last_check).days < 1:
                return cached
        
        # 2. Live Lookup with Rate Limit Backoff
        reputation = self._perform_check(normalized_type, ioc_value)
        
        # 3. Save & Return
        if reputation:
            self._save_cache(normalized_type, ioc_value, reputation)
        return reputation

    def _perform_check(self, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
        results = []
        
        # 1. VirusTotal V3 (IPs, Domains, Hashes)
        if self.vt_api_key:
            vt_res = self._query_virustotal(ioc_type, ioc_value)
            if vt_res: results.append(vt_res)
            # Free Tier: 4 req/min. We wait 15s to be safe if calling in a loop.
            time.sleep(15) 

        # 2. AbuseIPDB V2 (IPs Only)
        if ioc_type == "ip" and self.abuse_api_key:
            abuse_res = self._query_abuseipdb(ioc_value)
            if abuse_res: results.append(abuse_res)

        return self._calculate_final_score(ioc_type, ioc_value, results)

    def _query_virustotal(self, ioc_type: str, ioc_value: str) -> Optional[Dict]:
        """Queries VirusTotal v3 API."""
        # VT v3 endpoints
        endpoints = {
            "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{ioc_value}",
            "file": f"https://www.virustotal.com/api/v3/files/{ioc_value}"
        }
        
        url = endpoints.get(ioc_type)
        if not url: return None

        headers = {"x-apikey": self.vt_api_key, "accept": "application/json"}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                stats = response.json()["data"]["attributes"]["last_analysis_stats"]
                return {
                    "provider": "VirusTotal",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "total_engines": sum(stats.values())
                }
            elif response.status_code == 429:
                logger.warning("VirusTotal Rate Limit Hit (429).")
        except Exception as e:
            logger.error(f"VirusTotal query error: {e}")
        return None

    def _query_abuseipdb(self, ip: str) -> Optional[Dict]:
        """Queries AbuseIPDB v2 API."""
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers = {"Key": self.abuse_api_key, "Accept": "application/json"}

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()["data"]
                return {
                    "provider": "AbuseIPDB",
                    "abuse_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0)
                }
        except Exception as e:
            logger.error(f"AbuseIPDB query error: {e}")
        return None

    def _calculate_final_score(self, ioc_type: str, ioc_value: str, provider_data: List[Dict]) -> Dict[str, Any]:
        """Aggregates mult-provider data into a single threat level."""
        threat_level = "clear"
        max_malicious_count = 0
        
        for data in provider_data:
            # VT Logic: If > 3 engines flag it
            if data.get("provider") == "VirusTotal" and data.get("malicious", 0) > 3:
                threat_level = "malicious"
            # AbuseIPDB Logic: If confidence > 50%
            if data.get("provider") == "AbuseIPDB" and data.get("abuse_score", 0) > 50:
                threat_level = "malicious"

        return {
            "threat_level": threat_level,
            "is_malicious": threat_level == "malicious",
            "provider_raw": provider_data,
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