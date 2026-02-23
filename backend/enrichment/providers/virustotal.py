import requests
import time
from typing import Any, Dict
from backend.enrichment.base_provider import BaseEnrichmentProvider, logger
from backend.core.config import settings

class VirusTotalEnricher(BaseEnrichmentProvider):
    def __init__(self):
        super().__init__(provider_name="VirusTotal", cache_dir_name="virustotal")
        # Pulls from Settings class in config.py
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.delay = settings.VT_RATE_LIMIT_DELAY

    def get_data(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        ioc_type = ioc.get("type")
        ioc_value = ioc.get("value")
        
        # 1. Check local cache first
        cached = self._load_cache(ioc_type, ioc_value)
        if cached:
            return cached

        # 2. Guardrail: Skip if no API key is configured
        if not self.api_key:
            return {"status": "error", "reason": "API Key missing in .env"}

        # Map CTI types to VT v3 API endpoints
        endpoints = {
            "ipv4": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{ioc_value}",
            "file": f"https://www.virustotal.com/api/v3/files/{ioc_value}"
        }
        
        url = endpoints.get(ioc_type)
        if not url:
            return {"status": "skipped", "reason": f"Type '{ioc_type}' not supported by VT"}

        headers = {
            "x-apikey": self.api_key,
            "accept": "application/json"
        }
        
        try:
            # Respect the rate limit delay from config.py
            logger.info(f"VT lookup for {ioc_value}... (Rate limit delay: {self.delay}s)")
            time.sleep(self.delay) 
            
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                attr = response.json()["data"]["attributes"]
                stats = attr.get("last_analysis_stats", {})
                
                result = {
                    "malicious_count": stats.get("malicious", 0),
                    "suspicious_count": stats.get("suspicious", 0),
                    "harmless_count": stats.get("harmless", 0),
                    "reputation_score": attr.get("reputation", 0),
                    "tags": attr.get("tags", []),
                    "provider": "VirusTotal",
                    "lookup_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
                }
                self._save_cache(ioc_type, ioc_value, result)
                return result
            elif response.status_code == 404:
                return {"status": "not_found", "message": "IOC not seen by VT"}
                
        except Exception as e:
            logger.error(f"VirusTotal Provider Error: {e}")
            
        return {"status": "error"}  