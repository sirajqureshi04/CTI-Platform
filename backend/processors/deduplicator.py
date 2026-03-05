import json
import pickle
from pathlib import Path
from datetime import datetime
from typing import Dict, List

# Use the settings object we configured earlier
from backend.core.config import settings

SOURCE_MAP = {
    "vulnerability_parser": "CISA KEV",
    "cisa_kev": "CISA KEV",
    "ransomware_parser": "Ransomware.live",
    "ransomware": "Ransomware.live",
    "ransomware_onion": "DarkWeb Onion Scraper",
    "malpedia": "Malpedia",
    "alienvault_parser": "AlienVault OTX",
    "unknown": "Community OSINT"
}

class Deduplicator:
    def __init__(self, cache_dir: Path = None):
        # Use CURRENT_FINAL_DIR from config (storage/final/dd-mm-yy/)
        self.final_dir = settings.CURRENT_FINAL_DIR
        self.cache_dir = cache_dir or (settings.PROJECT_ROOT / "backend" / "cache" / "deduplication")
        
        # Ensure directories exist
        settings.ensure_dirs()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self._cached_records = {}
        self._load_cache()

    def deduplicate(self, iocs: List[Dict]) -> List[Dict]:
        """Merges IOCs and outputs to storage/final/dd-mm-yy/single.json"""
        for ioc in iocs:
            val = ioc.get("ioc_value") or ioc.get("value")
            if not val: continue
            
            raw_src = ioc.get("source") or ioc.get("name") or "unknown"
            clean_src = SOURCE_MAP.get(raw_src, raw_src)

            if val in self._cached_records:
                master = self._cached_records[val]
                if clean_src not in master.get("sources", []): 
                    master.setdefault("sources", []).append(clean_src)
                master["last_seen"] = datetime.now().isoformat()
            else:
                self._cached_records[val] = {
                    "value": val,
                    "type": ioc.get("ioc_type") or ioc.get("type", "unknown"),
                    "sources": [clean_src],
                    "last_seen": datetime.now().isoformat(),
                    "hit_count": 1
                }
        
        self._save_cache()
        
        # Save to the dated folder
        output_path = self.final_dir / "single.json"
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(list(self._cached_records.values()), f, indent=4)
            
        return list(self._cached_records.values())

    def _load_cache(self):
        cache_file = self.cache_dir / "master_records.pkl"
        if cache_file.exists():
            with open(cache_file, "rb") as f:
                self._cached_records = pickle.load(f)

    def _save_cache(self):
        with open(self.cache_dir / "master_records.pkl", "wb") as f:
            pickle.dump(self._cached_records, f)