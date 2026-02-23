import json
import os 
import requests
import ipaddress
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime

# Industry standard for GeoIP
try:
    import geoip2.database
    HAS_GEOIP_LIB = True
except ImportError:
    HAS_GEOIP_LIB = False

from backend.core.logger import CTILogger
from backend.core.config import settings

logger = CTILogger.get_logger(__name__)

class GeoIPEnricher: # Renamed to match Manager's expectations
    """
    Performs GeoIP lookups for IP addresses.
    Priority: Local MaxMind DB -> Local Cache -> Public API Fallback.
    """
    
    def __init__(self, cache_dir: Optional[Path] = None):
        # 1. Setup Caching path
        base_path = getattr(settings, "BASE_DIR", os.getcwd())
        if cache_dir is None:
            self.cache_dir = Path(base_path) / "backend" / "cache" / "enrichment" / "ip"
        else:
            self.cache_dir = Path(cache_dir)
        
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # 2. Initialize MaxMind Reader
        self.db_path = Path(base_path) / "resources" / "GeoLite2-City.mmdb"
        self.reader = None
        
        if HAS_GEOIP_LIB and self.db_path.exists():
            try:
                self.reader = geoip2.database.Reader(str(self.db_path))
                logger.info(f"Initialized MaxMind DB from {self.db_path}")
            except Exception as e:
                logger.error(f"Failed to load MaxMind DB: {e}")
        else:
            logger.warning("MaxMind DB missing. Using Public API fallback for dry run.")

    def get_data(self, ip: str) -> Dict[str, Any]:
        """
        Main entry point called by EnrichmentManager.
        """
        # Validate IP format & skip private ranges (RFC1918)
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return {"status": "skipped", "note": "Private/Internal IP"}
        except ValueError:
            return {"status": "error", "note": "Invalid IP format"}

        # 1. Check local JSON cache first
        cached = self._load_cache(ip)
        if cached:
            return cached
        
        # 2. Perform Lookup (DB or API)
        geo_info = self._perform_lookup(ip)
        
        # 3. Save to Cache
        self._save_cache(ip, geo_info)
        
        return geo_info

    def _perform_lookup(self, ip: str) -> Dict[str, Any]:
        """Queries MaxMind or falls back to an HTTP API."""
        data = {
            "country": "Unknown",
            "country_code": "XX",
            "city": "Unknown",
            "latitude": None,
            "longitude": None,
            "provider": "Unknown",
            "lookup_timestamp": datetime.utcnow().isoformat()
        }

        # Attempt MaxMind Local Lookup
        if self.reader:
            try:
                response = self.reader.city(ip)
                data.update({
                    "country": response.country.name,
                    "country_code": response.country.iso_code,
                    "city": response.city.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                    "provider": "MaxMind Local"
                })
                return data
            except Exception:
                logger.debug(f"IP {ip} not in local DB, trying API...")

        # Fallback to Public API (Useful for Dry Runs)
        try:
            # ip-api.com is free for non-commercial use, no key needed
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
            if resp.get("status") == "success":
                data.update({
                    "country": resp.get("country"),
                    "country_code": resp.get("countryCode"),
                    "city": resp.get("city"),
                    "latitude": resp.get("lat"),
                    "longitude": resp.get("lon"),
                    "provider": "ip-api.com"
                })
        except Exception as e:
            logger.error(f"API Fallback failed for {ip}: {e}")
        
        return data

    def _load_cache(self, ip: str) -> Optional[Dict[str, Any]]:
        cache_file = self.cache_dir / f"{ip.replace('.', '_')}.json"
        if cache_file.exists():
            try:
                with open(cache_file, "r") as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    def _save_cache(self, ip: str, geo_info: Dict[str, Any]) -> None:
        cache_file = self.cache_dir / f"{ip.replace('.', '_')}.json"
        try:
            with open(cache_file, "w") as f:
                json.dump(geo_info, f, indent=2)
        except Exception as e:
            logger.warning(f"Cache save failed for {ip}: {e}")

    def __del__(self):
        """Ensure reader is closed when object is destroyed."""
        if hasattr(self, 'reader') and self.reader:
            self.reader.close()