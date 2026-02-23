import requests
from typing import Any, Dict
from backend.enrichment.base_provider import BaseEnrichmentProvider, logger
from backend.core.config import settings

class AbuseIPDBEnricher(BaseEnrichmentProvider):
    def __init__(self):
        super().__init__(provider_name="AbuseIPDB", cache_dir_name="abuseipdb")
        # Pulls from Settings class in config.py
        self.api_key = settings.ABUSEIPDB_API_KEY

    def get_data(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        ioc_type = ioc.get("type")
        ioc_value = ioc.get("value")

        if ioc_type not in ["ipv4", "ipv6"]:
            return {"status": "skipped", "reason": "AbuseIPDB only supports IP addresses"}

        # 1. Check local cache
        cached = self._load_cache("ip", ioc_value)
        if cached:
            return cached

        # 2. Guardrail: Skip if no API key is configured
        if not self.api_key:
            return {"status": "error", "reason": "API Key missing in .env"}

        url = "https://api.abuseipdb.com/api/v2/check"
        params = {
            "ipAddress": ioc_value,
            "maxAgeInDays": "90",
            "verbose": "false"
        }
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                result = {
                    "abuse_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "last_reported": data.get("lastReportedAt"),
                    "isp": data.get("isp"),
                    "is_whitelisted": data.get("isWhitelisted"),
                    "provider": "AbuseIPDB",
                    "lookup_timestamp": data.get("generatedAt")
                }
                self._save_cache("ip", ioc_value, result)
                return result
            
        except Exception as e:
            logger.error(f"AbuseIPDB Provider Error: {e}")

        return {"status": "error"}