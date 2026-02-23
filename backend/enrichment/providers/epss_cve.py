import requests
from typing import Any, Dict, Optional
from backend.enrichment.base_provider import BaseEnrichmentProvider, logger

class EPSSEnricher(BaseEnrichmentProvider):
    """
    Enriches CVE IDs with Exploit Prediction Scoring System data.
    """
    def __init__(self):
        # EPSS data is updated daily; 1 day TTL is ideal.
        super().__init__(provider_name="EPSS", cache_dir_name="epss")

    def get_data(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        if ioc.get("type") != "cve":
            return {"status": "skipped", "reason": "not a cve"}

        cve_id = ioc.get("value").upper()
        cached = self._load_cache("cve", cve_id)
        if cached: return cached

        # First.org API for EPSS
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"

        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json().get("data", [])
                if data:
                    epss_info = data[0]
                    result = {
                        "epss_score": float(epss_info.get("epss", 0)),
                        "percentile": float(epss_info.get("percentile", 0)),
                        "date": epss_info.get("date"),
                        "provider": "EPSS"
                    }
                    self._save_cache("cve", cve_id, result)
                    return result
        except Exception as e:
            logger.error(f"EPSS Error: {e}")
        return {"status": "error", "message": "CVE not found in EPSS"}