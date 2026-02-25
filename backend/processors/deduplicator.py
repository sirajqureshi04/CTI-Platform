import json
import pickle
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# FIXED: Comprehensive mapping of internal parser names to professional sources
SOURCE_MAP = {
    # CISA Parser naming variations
    "vulnerability_parser": "CISA KEV",
    "cisa_kev": "CISA KEV",
    
    # Ransomware Parser naming variations
    "ransomware_parser": "Ransomware.live",
    "ransomware": "Ransomware.live",
    
    # Other parsers
    "malpedia": "Malpedia",
    "alienvault_parser": "AlienVault OTX",
    "alienvault_otx": "AlienVault OTX",
    
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
        Merges IOCs and outputs a single daily file: DD-MM-YYYY_single.json
        """
        for ioc in iocs:
            # Handle different field names for the indicator value
            val = ioc.get("ioc_value") or ioc.get("value")
            if not val: 
                continue
            
            # Resolve the raw source string from possible keys
            raw_src = ioc.get("source") or ioc.get("name") or "unknown"
            
            # Use SOURCE_MAP to get the clean name, or fallback to raw_src
            clean_src = SOURCE_MAP.get(raw_src, raw_src)

            if val in self._cached_records:
                master = self._cached_records[val]
                
                # Update sources list (unique set)
                if "sources" not in master:
                    master["sources"] = []
                if clean_src not in master["sources"]: 
                    master["sources"].append(clean_src)
                
                # Merge tags from metadata or direct keys
                incoming_tags = ioc.get("metadata", {}).get("tags", []) or ioc.get("tags", [])
                master["tags"] = list(set(master.get("tags", []) + incoming_tags))
                
                # Update hit count and timestamp
                master["last_seen"] = datetime.now().isoformat()
                master["hit_count"] = len(master["sources"])
            else:
                # Initialize new record with your ProcessedIndicator schema
                self._cached_records[val] = {
                    "value": val,
                    "type": ioc.get("ioc_type") or ioc.get("type", "unknown"),
                    "sources": [clean_src],
                    "severity": ioc.get("metadata", {}).get("severity") or ioc.get("severity", "medium"),
                    "confidence": ioc.get("metadata", {}).get("confidence") or ioc.get("confidence", 50),
                    "last_seen": datetime.now().isoformat(),
                    "tags": ioc.get("metadata", {}).get("tags", []) or ioc.get("tags", []),
                    "hit_count": 1
                }
        
        self._save_cache()
        
        # SAVE LOGIC: 24-02-2026_single.json format
        current_date_str = datetime.now().strftime("%d-%m-%Y")
        output_path = self.final_dir / f"{current_date_str}_single.json"
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(list(self._cached_records.values()), f, indent=4)
            
        return list(self._cached_records.values())

    def _load_cache(self):
        cache_file = self.cache_dir / "master_records.pkl"
        if cache_file.exists():
            try:
                with open(cache_file, "rb") as f:
                    self._cached_records = pickle.load(f)
            except Exception as e:
                print(f"⚠️ Cache load failed: {e}. Starting fresh.")
                self._cached_records = {}

    def _save_cache(self):
        with open(self.cache_dir / "master_records.pkl", "wb") as f:
            pickle.dump(self._cached_records, f)