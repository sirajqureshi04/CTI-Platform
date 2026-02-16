import json
import pickle
from pathlib import Path
from typing import Dict, List, Any

# 1. Update your Source Map here
SOURCE_MAP = {
    "vulnerability_parser": "CISA KEV",
    "malpedia": "Malpedia",
    "ransomware_parser": "Ransomware.live",
    "unknown": "Community OSINT"
}

class Deduplicator:
    def __init__(self, cache_dir: Path = None):
        # Resolve the root directory of your project
        # This assumes deduplicator.py is in backend/processors/
        self.root_dir = Path(__file__).resolve().parent.parent.parent
        
        # Ensure cache and storage directories are absolute
        self.cache_dir = cache_dir or self.root_dir / "backend" / "cache" / "deduplication"
        self.final_dir = self.root_dir / "storage" / "final"
        
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.final_dir.mkdir(parents=True, exist_ok=True)
        
        self._cached_records: Dict[str, Dict[str, Any]] = {}
        self._load_cache()

    def _load_cache(self):
        cache_file = self.cache_dir / "master_records.pkl"
        if cache_file.exists():
            with open(cache_file, "rb") as f:
                self._cached_records = pickle.load(f)

    def _save_cache(self):
        with open(self.cache_dir / "master_records.pkl", "wb") as f:
            pickle.dump(self._cached_records, f)

    def deduplicate(self, iocs: List[Dict]) -> List[Dict]:
        """
        Processes IOCs: Standardizes ID to 'value', renames sources via mapping,
        and saves output to storage/final/final_intelligence.json.
        """
        for ioc in iocs:
            # FIX: Force use of 'value' as identifier
            val = ioc.get("value")
            if not val:
                continue
            
            # FIX: Map the source names immediately
            raw_src = ioc.get("source") or (ioc.get("sources")[0] if ioc.get("sources") else "unknown")
            clean_src = SOURCE_MAP.get(raw_src, raw_src)

            if val in self._cached_records:
                master = self._cached_records[val]
                # Ensure 'sources' exists as a list in the master record
                if "sources" not in master:
                    master["sources"] = []
                
                if clean_src not in master["sources"]:
                    master["sources"].append(clean_src)
                
                # Merge tags
                master["tags"] = list(set(master.get("tags", []) + ioc.get("tags", [])))
            else:
                # First time seeing this IOC
                ioc["sources"] = [clean_src]
                ioc.pop("source", None) # Remove singular key
                self._cached_records[val] = ioc
        
        self._save_cache()
        
        # FIX: Explicitly save to the storage/final folder
        output_file = self.final_dir / "final_intelligence.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(list(self._cached_records.values()), f, indent=4)
            
        print(f"✅ Success: Data saved to {output_file}")
        return list(self._cached_records.values())