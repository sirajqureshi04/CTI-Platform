import json
import pickle
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# factor 3: Map internal parser keys to professional display sources
SOURCE_MAP = {
    "cisa_parser": "CISA KEV",
    "alienvault_parser": "AlienVault OTX",
    "malpedia": "Malpedia",
    "ransomware_parser": "Ransomware.live",
    "unknown": "Community OSINT"
}

class Deduplicator:
    def __init__(self, cache_dir: Path = None):
        self.root_dir = Path(__file__).resolve().parents[2] 
        self.final_dir = self.root_dir / "storage" / "final"
        self.cache_dir = cache_dir or (self.root_dir / "backend" / "cache" / "deduplication")
        
        self.final_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self._cached_records = {}
        self._load_cache()

    def deduplicate(self, iocs: List[Dict]) -> List[Dict]:
        """
        Merges IOCs and outputs unique daily files.
        """
        for ioc in iocs:
            val = ioc.get("value")
            if not val: continue
            
            # Factor 1 & 3: Resolve specific parser name to clean display name
            raw_src = ioc.get("source") or (ioc.get("sources")[0] if ioc.get("sources") else "unknown")
            clean_src = SOURCE_MAP.get(raw_src, raw_src)

            if val in self._cached_records:
                master = self._cached_records[val]
                if "sources" not in master: master["sources"] = []
                if clean_src not in master["sources"]: 
                    master["sources"].append(clean_src)
                
                # Merge tags and update timestamp
                master["tags"] = list(set(master.get("tags", []) + ioc.get("tags", [])))
                master["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            else:
                # Initialize new record with mapped source
                ioc["sources"] = [clean_src]
                ioc.pop("source", None) # Remove technical parser name
                ioc["first_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self._cached_records[val] = ioc
        
        self._save_cache()
        
        # Factor 2: Save as separate JSON files with the date
        current_date = datetime.now().strftime("%Y-%m-%d")
        output_path = self.final_dir / f"intel_report_{current_date}.json"
        
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