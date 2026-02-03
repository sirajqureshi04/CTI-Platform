"""
GeoIP lookup enrichment for IP addresses.
Integrated with EnrichmentManager and optimized with local caching.
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime
import ipaddress

# Industry standard for GeoIP
try:
    import geoip2.database
    HAS_GEOIP_LIB = True
except ImportError:
    HAS_GEOIP_LIB = False

from backend.core.logger import CTILogger
from backend.core.config import settings

logger = CTILogger.get_logger(__name__)

class GeoIPLookup:
    """
    Performs GeoIP lookups for IP addresses.
    Uses local MaxMind DBs with a fallback to a JSON cache.
    """
    
    def __init__(self, cache_dir: Optional[Path] = None):
        # 1. Setup Caching
        if cache_dir is None:
            # Aligned with your project structure
            self.cache_dir = Path(settings.BASE_DIR) / "cache" / "enrichment" / "ip"
        else:
            self.cache_dir = Path(cache_dir)
        
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # 2. Initialize MaxMind Reader (GeoLite2-City.mmdb)
        # Ensure you have this file in your resources folder
        self.db_path = Path(settings.BASE_DIR) / "resources" / "GeoLite2-City.mmdb"
        self.reader = None
        
        if HAS_GEOIP_LIB and self.db_path.exists():
            try:
                self.reader = geoip2.database.Reader(str(self.db_path))
                logger.info(f"Initialized MaxMind DB from {self.db_path}")
            except Exception as e:
                logger.error(f"Failed to load MaxMind DB: {e}")
        else:
            logger.warning("MaxMind DB not found. Falling back to cache-only/mock lookups.")

    def lookup(self, ip: str) -> Dict[str, Any]:
        """
        Lookup geographic information for an IP address.
        Called by EnrichmentManager.
        """
        # Validate IP format
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return {"ip": ip, "note": "Private/Internal IP", "status": "skipped"}
        except ValueError:
            return {"ip": ip, "error": "Invalid IP format", "status": "error"}

        # Check Cache
        cached = self._load_cache(ip)
        if cached:
            return cached
        
        # Perform Real Lookup
        geo_info = self._perform_lookup(ip)
        
        # Save to Cache
        self._save_cache(ip, geo_info)
        
        return geo_info

    def _perform_lookup(self, ip: str) -> Dict[str, Any]:
        """The actual engine that queries MaxMind or a fallback."""
        data = {
            "ip": ip,
            "country": "Unknown",
            "country_code": "XX",
            "city": "Unknown",
            "latitude": None,
            "longitude": None,
            "asn": None,
            "lookup_timestamp": datetime.utcnow().isoformat()
        }

        if self.reader:
            try:
                response = self.reader.city(ip)
                data.update({
                    "country": response.country.name,
                    "country_code": response.country.iso_code,
                    "city": response.city.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                })
            except Exception as e:
                logger.debug(f"IP {ip} not found in database: {e}")
        
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

    def close(self):
        """Clean up resources."""
        if self.reader:
            self.reader.close()
