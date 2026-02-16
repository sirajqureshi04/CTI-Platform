import sys
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

# Ensure **project root** (directory that contains `backend/`) is in path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

# Parsers & unified model
from backend.parser.ransomware_parser import RansomwareParser
from backend.parser.vulnerability_parser import VulnerabilityParser
from backend.parser.malware_parser import MalwareParser
from backend.models.indcator import ProcessedIndicator


RAW_BASE = PROJECT_ROOT / "storage" / "raw"
PROCESSED_BASE = PROJECT_ROOT / "storage" / "processed"


def get_parser_for_feed(feed_name: str):
    """Return an appropriate parser instance for a given raw folder name."""
    name = feed_name.lower()
    if name in {"ransomware_live", "ransomware"}:
        return RansomwareParser()
    if name in {"otx", "alienvault_otx"}:
        # OTX pulses → vulnerabilities (CVEs)
        return VulnerabilityParser()
    if name in {"malpedia", "malware"}:
        return MalwareParser()
    if name in {"cisa", "cisa_kev"}:
        return VulnerabilityParser()
    return None


def to_processed_indicators(parsed_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Map normalized parser output into the unified ProcessedIndicator schema."""
    processed: List[Dict[str, Any]] = []

    for item in parsed_items:
        ioc_type = item.get("ioc_type", "unknown")
        ioc_value = item.get("ioc_value", "")
        source = item.get("source", "unknown")
        metadata = item.get("metadata", {}) or {}

        # Derive optional fields for the UDM
        tags = metadata.get("tags", [])
        if not isinstance(tags, list):
            tags = [str(tags)]

        pi = ProcessedIndicator(
            value=str(ioc_value),
            type=str(ioc_type),
            source=str(source),
            severity=metadata.get("severity", "medium"),
            confidence=int(metadata.get("confidence", 50)),
            tags=tags,
        )
        processed.append(pi.model_dump())

    return processed


def save_processed(feed_name: str, raw_filename: str, records: List[Dict[str, Any]]):
    """
    Save processed indicators into storage/processed/<feed_name>/<matching-filename>.json
    so the processed tree mirrors the structure and filenames of storage/raw.
    """
    if not records:
        return

    target_dir = PROCESSED_BASE / feed_name
    target_dir.mkdir(parents=True, exist_ok=True)

    # Preserve the original date-stamped filename pattern but mark it as processed
    stem = Path(raw_filename).stem.replace("_raw", "")
    filename = f"{stem}_processed.json"
    filepath = target_dir / filename

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=4, default=str)

    print(f"💾 Saved {len(records)} indicators to {filepath}")


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

        json_files = sorted(feed_dir.glob("*.json"))
        if not json_files:
            continue

        print(f"\n📂 Feed Source: [{feed_name}] ({len(json_files)} files)")

        for raw_file in json_files:
            print(f"   ⚙️ Parsing: {raw_file.name}")
            try:
                with open(raw_file, "r", encoding="utf-8") as f:
                    wrapper = json.load(f)

                # Stored structure: {"metadata": {...}, "data": <feed_payload>}
                feed_payload = wrapper.get("data", {})
                parsed_items = parser.parse(feed_payload)
                processed_batch = to_processed_indicators(parsed_items)
                save_processed(feed_name, raw_file.name, processed_batch)

            except Exception as e:
                print(f"   🔥 Error in {raw_file.name}: {e}")

        print("-" * 60)


if __name__ == "__main__":
    process_all_raw()