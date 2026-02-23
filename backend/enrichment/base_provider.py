import json
import hashlib
from abc import ABC, abstractmethod
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional

from backend.core.logger import CTILogger
from backend.core.config import settings

logger = CTILogger.get_logger(__name__)

class BaseEnrichmentProvider(ABC):
    """
    Abstract Base Class for all CTI Enrichment Providers.
    Provides shared caching logic and enforces a standard interface.
    """

    def __init__(self, provider_name: str, cache_dir_name: str, cache_ttl_days: int = 1):
        self.provider_name = provider_name
        self.cache_ttl_days = cache_ttl_days
        
        # Setup Cache Directory
        base_path = getattr(settings, "BASE_DIR", ".")
        self.cache_dir = Path(base_path) / "backend" / "cache" / "enrichment" / cache_dir_name
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Provider '{self.provider_name}' initialized.")

    @abstractmethod
    def get_data(self, ioc_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point. Subclasses MUST implement this.
        Should return a dictionary of enriched data.
        """
        pass

    def _get_cache_key(self, ioc_type: str, ioc_value: str) -> str:
        """Generates a consistent SHA-256 hash for filenames."""
        return hashlib.sha256(f"{ioc_type}:{ioc_value}".encode()).hexdigest()

    def _load_cache(self, ioc_type: str, ioc_value: str) -> Optional[Dict]:
        """Loads data if it exists and hasn't expired."""
        cache_file = self.cache_dir / f"{self._get_cache_key(ioc_type, ioc_value)}.json"
        
        if cache_file.exists():
            try:
                with open(cache_file, "r") as f:
                    data = json.load(f)
                
                # Check TTL
                timestamp_str = data.get("lookup_timestamp") or data.get("check_timestamp")
                if timestamp_str:
                    last_check = datetime.fromisoformat(timestamp_str)
                    if (datetime.utcnow() - last_check).days < self.cache_ttl_days:
                        return data
            except Exception as e:
                logger.warning(f"[{self.provider_name}] Cache read error: {e}")
        
        return None

    def _save_cache(self, ioc_type: str, ioc_value: str, data: Dict):
        """Saves enriched results to the provider-specific cache folder."""
        cache_file = self.cache_dir / f"{self._get_cache_key(ioc_type, ioc_value)}.json"
        try:
            # Ensure a timestamp is present for future TTL checks
            if "lookup_timestamp" not in data and "check_timestamp" not in data:
                data["lookup_timestamp"] = datetime.utcnow().isoformat()
                
            with open(cache_file, "w") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"[{self.provider_name}] Failed to save cache: {e}")