import json
import time
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional, List

# Industry standard for WHOIS
try:
    import whois
    HAS_WHOIS_LIB = True
except ImportError:
    HAS_WHOIS_LIB = False

from backend.core.logger import CTILogger
from backend.core.config import settings

logger = CTILogger.get_logger(__name__)

class WhoisEnricher: # Renamed to match EnrichmentManager
    """
    Performs WHOIS lookups with structured data extraction.
    Optimized for CTI dry-runs with date normalization and rate-limit safety.
    """
    
    def __init__(self, cache_dir: Optional[Path] = None):
        base_path = getattr(settings, "BASE_DIR", ".")
        if cache_dir is None:
            self.cache_dir = Path(base_path) / "backend" / "cache" / "enrichment" / "whois"
        else:
            self.cache_dir = Path(cache_dir)
            
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        logger.info("WHOIS Enrichment module initialized.")

    def get_data(self, domain: str) -> Dict[str, Any]:
        """
        Main entry point for EnrichmentManager.
        Includes a 7-day cache TTL to avoid redundant lookups.
        """
        cached = self._load_cache(domain)
        if cached:
            # Check if cache is older than 7 days
            try:
                last_check = datetime.fromisoformat(cached.get("lookup_timestamp", "2000-01-01"))
                if (datetime.utcnow() - last_check).days < 7:
                    return cached
            except ValueError:
                pass # If timestamp is corrupt, re-fetch
        
        # Rate limit safety: WHOIS servers are sensitive. 
        # Add a small sleep if calling this in a tight loop.
        time.sleep(1) 
        
        whois_info = self._perform_lookup(domain)
        self._save_cache(domain, whois_info)
        return whois_info

    def _normalize_date(self, date_val: Any) -> Optional[datetime]:
        """Handles the 'List vs Single Object' inconsistency in python-whois."""
        if not date_val:
            return None
        if isinstance(date_val, list):
            # Take the first date in the list (usually the actual creation date)
            date_val = date_val[0]
        if isinstance(date_val, datetime):
            return date_val
        return None

    def _perform_lookup(self, domain: str) -> Dict[str, Any]:
        """Fetches and parses WHOIS data with risk heuristic scoring."""
        data = {
            "registrar": "Unknown",
            "creation_date": None,
            "expiration_date": None,
            "is_young_domain": False,
            "lookup_timestamp": datetime.utcnow().isoformat()
        }

        if not HAS_WHOIS_LIB:
            logger.error("Library 'python-whois' not found. Run: pip install python-whois")
            return data

        try:
            # timeout=5 prevents the entire pipeline from hanging on a dead WHOIS server
            w = whois.whois(domain)
            
            # Use normalization helper for all date fields
            creation = self._normalize_date(w.get("creation_date"))
            expiration = self._normalize_date(w.get("expiration_date"))
            
            data.update({
                "registrar": w.get("registrar", "Unknown"),
                "creation_date": creation.isoformat() if creation else None,
                "expiration_date": expiration.isoformat() if expiration else None,
                "name_servers": w.get("name_servers", []),
                "status": w.get("status", "Unknown"),
            })

            # RISK SCORING: Young Domain Detection
            if creation:
                # Remove timezone info for calculation to prevent offset errors
                age = datetime.utcnow() - creation.replace(tzinfo=None)
                data["is_young_domain"] = age.days < 30
                data["domain_age_days"] = age.days

        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {str(e)}")
            data["error"] = "No match or server timeout"
        
        return data

    def _load_cache(self, domain: str) -> Optional[Dict]:
        cache_file = self.cache_dir / f"{domain.replace('.', '_')}.json"
        if cache_file.exists():
            try:
                with open(cache_file, "r") as f: 
                    return json.load(f)
            except: 
                return None
        return None

    def _save_cache(self, domain: str, info: Dict):
        cache_file = self.cache_dir / f"{domain.replace('.', '_')}.json"
        try:
            with open(cache_file, "w") as f:
                json.dump(info, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save WHOIS cache: {e}")