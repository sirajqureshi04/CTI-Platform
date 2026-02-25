import sys
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

# Ensure **project root** is in path so we can import 'backend'
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Parsers & unified model
from backend.parser.ransomware_parser import RansomwareParser
from backend.parser.alienvault_otx_parser import AlienVaultOTXParser
from backend.parser.cisa_kev_parser import CISAKEVParser
from backend.parser.malpedia_parser import MalpediaParser
from backend.models.indicator import ProcessedIndicator

# Standardized Paths
RAW_BASE = PROJECT_ROOT / "storage" / "raw"
PROCESSED_BASE = PROJECT_ROOT / "storage" / "processed"

def get_parser_for_feed(feed_name: str):
    """
    Return an appropriate parser instance for a given raw folder name.
    Fixes the instantiation error by mapping folder names to corrected Parser classes.
    """
    name = feed_name.lower()
    
    if name in {"ransomware_live", "ransomware"}:
        return RansomwareParser()
    
    if name in {"otx", "alienvault_otx"}:
        # Resolves the TypeError: Can't instantiate abstract class
        return AlienVaultOTXParser()
    
    if name in {"malpedia", "malware"}:
        # Corrected from 'MalwareParser' to 'MalpediaParser'
        return MalpediaParser()
    
    if name in {"cisa", "cisa_kev"}:
        return CISAKEVParser()
    
    return None

def to_processed_indicators(parsed_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Map normalized parser output into the unified ProcessedIndicator schema.
    Aligned with BaseParser.normalize_ioc keys: 'ioc_type' and 'ioc_value'.
    """
    processed: List[Dict[str, Any]] = []

    for item in parsed_items:
        # These keys come from BaseParser.normalize_ioc
        ioc_type = item.get("ioc_type", "unknown")
        ioc_value = item.get("ioc_value", "")
        source = item.get("source", "unknown")
        metadata = item.get("metadata", {}) or {}

        # Build the Pydantic model for validation
        try:
            pi = ProcessedIndicator(
                value=str(ioc_value),
                type=str(ioc_type),
                source=str(source),
                severity=metadata.get("severity", "medium"),
                confidence=int(metadata.get("confidence", 50)),
                tags=metadata.get("tags", []),
            )
            processed.append(pi.model_dump())
        except Exception as e:
            print(f"      ⚠️ Validation Error for indicator {ioc_value}: {e}")

    return processed

def save_processed(feed_name: str, raw_filename: str, records: List[Dict[str, Any]]):
    """
    Save processed indicators into storage/processed/<feed_name>/<date>_processed.json.
    Mirrors the storage/raw tree structure.
    """
    if not records:
        return

    target_dir = PROCESSED_BASE / feed_name
    target_dir.mkdir(parents=True, exist_ok=True)

    # Convert 2026-02-24_raw.json -> 2026-02-24_processed.json
    stem = Path(raw_filename).stem.replace("_raw", "")
    filename = f"{stem}_processed.json"
    filepath = target_dir / filename

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=4, default=str)

    print(f"  💾 Saved {len(records)} indicators to {filepath}")

def process_all_raw():
    """Walk storage/raw, parse each feed folder, and write to storage/processed."""
    print(f"🛡️ Starting Raw → Processed pipeline from {RAW_BASE}...\n")

    if not RAW_BASE.exists():
        print(f"❌ Raw base directory does not exist: {RAW_BASE}")
        return

    for feed_dir in RAW_BASE.iterdir():
        if not feed_dir.is_dir():
            continue

        feed_name = feed_dir.name
        parser = get_parser_for_feed(feed_name)
        
        if not parser:
            print(f"⚠️ No parser configured for feed folder '{feed_name}', skipping.")
            continue

        # Get all JSON files (e.g., 2026-02-24_raw.json)
        json_files = sorted(feed_dir.glob("*.json"))
        if not json_files:
            continue

        print(f"\n📂 Feed Source: [{feed_name}] ({len(json_files)} files)")

        for raw_file in json_files:
            print(f"    ⚙️ Parsing: {raw_file.name}")
            try:
                with open(raw_file, "r", encoding="utf-8") as f:
                    wrapper = json.load(f)

                # Extracts the payload from the 'data' key saved by the feed
                feed_payload = wrapper.get("data", {})
                
                # Execute the parser's parse logic
                parsed_items = parser.parse(feed_payload)
                
                # Convert to unified schema
                processed_batch = to_processed_indicators(parsed_items)
                
                # Save to storage/processed/
                save_processed(feed_name, raw_file.name, processed_batch)

            except Exception as e:
                print(f"    🔥 Error in {raw_file.name}: {e}")

        print("-" * 60)

if __name__ == "__main__":
    process_all_raw()