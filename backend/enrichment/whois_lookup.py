"""
WHOIS lookup enrichment for domains.
Uses python-whois for structured parsing and provides age-based risk scoring.
"""

import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

# Industry standard for WHOIS
try:
    import whois
    HAS_WHOIS_LIB = True
except ImportError:
    HAS_WHOIS_LIB = False

from backend.core.logger import CTILogger
from backend.core.config import settings

logger = CTILogger.get_logger(__name__)

class WhoisLookup:
    """
    Performs WHOIS lookups with structured data extraction.
    Highlights 'Young Domains' which are high-risk indicators in phishing.
    """
    
    def __init__(self, cache_dir: Optional[Path] = None):
        if cache_dir is None:
            self.cache_dir = Path(settings.BASE_DIR) / "cache" / "enrichment" / "whois"
        else:
            self.cache_dir = Path(cache_dir)
            
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        logger.info("WHOIS Lookup engine ready.")

    def lookup(self, domain: str) -> Dict[str, Any]:
        """
        Main entry point. Standardized for EnrichmentManager.
        """
        # 1. Check Cache
        cached = self._load_cache(domain)
        if cached:
            # WHOIS is stable; 7-day TTL is usually sufficient
            last_check = datetime.fromisoformat(cached["lookup_timestamp"])
            if (datetime.utcnow() - last_check).days < 7:
                return cached
        
        # 2. Perform Live Lookup
        whois_info = self._perform_lookup(domain)
        
        # 3. Save to Cache
        self._save_cache(domain, whois_info)
        
        return whois_info

    def _perform_lookup(self, domain: str) -> Dict[str, Any]:
        """Fetches and parses WHOIS data using the whois library."""
        data = {
            "domain": domain,
            "registrar": "Unknown",
            "creation_date": None,
            "expiration_date": None,
            "is_young_domain": False,
            "raw_text": "",
            "lookup_timestamp": datetime.utcnow().isoformat()
        }

        if not HAS_WHOIS_LIB:
            logger.error("python-whois library not installed.")
            return data

        try:
            w = whois.whois(domain)
            
            # Handle list vs single value (some registrars return lists)
            creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            
            data.update({
                "registrar": w.registrar,
                "creation_date": creation.isoformat() if creation else None,
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "status": w.status[0] if isinstance(w.status, list) else w.status,
            })

            # Logic: If domain is less than 30 days old, flag as 'Young'
            if creation:
                age = datetime.utcnow() - creation.replace(tzinfo=None)
                data["is_young_domain"] = age.days < 30

        except Exception as e:
            logger.warning(f"WHOIS failed for {domain}: {e}")
            data["error"] = str(e)
        
        return data

    def _load_cache(self, domain: str) -> Optional[Dict]:
        cache_file = self.cache_dir / f"{domain.replace('.', '_')}.json"
        if cache_file.exists():
            try:
                with open(cache_file, "r") as f: return json.load(f)
            except: return None
        return None

    def _save_cache(self, domain: str, info: Dict):
        cache_file = self.cache_dir / f"{domain.replace('.', '_')}.json"
        with open(cache_file, "w") as f:
            json.dump(info, f, indent=2, default=str)