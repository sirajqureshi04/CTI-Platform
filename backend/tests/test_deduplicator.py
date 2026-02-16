import json
import sys
from pathlib import Path

# Ensure project root (directory that contains `backend/`) is on sys.path
# so `import backend` works when run from backend/ or from project root
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.processors.deduplicator import Deduplicator
from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)

def run_dry_run_test():
    processed_path = PROJECT_ROOT / "storage" / "processed"
    dedup = Deduplicator()
    all_raw_data = []

    print(f"--- 🔍 Scanning: {processed_path.absolute()} ---")

    # 3. FIX: Use rglob("*") to find files inside subfolders (cisa, malpedia, ransomware_live)
    if not processed_path.exists():
        print(f"❌ Error: {processed_path} folder not found.")
        return

    for file_path in processed_path.rglob("*.json"):
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                # Handle files that contain a single object or a list of objects
                if isinstance(data, list):
                    all_raw_data.extend(data)
                else:
                    all_raw_data.append(data)
                print(f"✅ Loaded {len(data) if isinstance(data, list) else 1} records from {file_path.name}")
            except Exception as e:
                print(f"❌ Failed to load {file_path.name}: {e}")

    if not all_raw_data:
        print("⚠️ No data found to deduplicate. Check your storage/processed subfolders.")
        return

    print(f"\n🚀 Total records found: {len(all_raw_data)}")

    # 4. ACTION: Run the fixed deduplication logic
    # This will now apply your Source Mapping and save to storage/final
    final_output = dedup.deduplicate(all_raw_data)

    print("\n--- 🧪 Dry Run Summary ---")
    print(f"Unique Records: {len(final_output)}")
    print(f"Duplicate/Merged Count: {len(all_raw_data) - len(final_output)}")
    print(f"Final file location: storage/final/final_intelligence.json")

    # 5. Spot check: Ensure sources are mapped correctly
    if final_output:
        print("\n--- 🕵️ Spot Check (First Record) ---")
        sample = final_output[0]
        print(f"Value: {sample.get('value')}")
        print(f"Mapped Sources: {sample.get('sources')}")

if __name__ == "__main__":
    run_dry_run_test()