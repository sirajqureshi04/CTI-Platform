import json
import sys
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.processors.deduplicator import Deduplicator
from backend.core.logger import CTILogger
logger = CTILogger.get_logger(__name__)

def run_final_merge():
    processed_path = PROJECT_ROOT / "storage" / "processed"
    dedup = Deduplicator()
    today_data = []

    # Format matches your parser output naming: YYYY-MM-DD
    today_str = datetime.now().strftime("%Y-%m-%d")
    
    print(f"--- 🔍 Collecting Processed Feeds for: {today_str} ---")

    if not processed_path.exists():
        print(f"❌ Error: {processed_path} folder not found.")
        return

    # Search for files containing today's date in their filename
    for file_path in processed_path.rglob(f"*{today_str}*.json"):
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                if isinstance(data, list):
                    today_data.extend(data)
                else:
                    today_data.append(data)
                print(f"✅ Loaded {len(data) if isinstance(data, list) else 1} records from {file_path.name}")
            except Exception as e:
                print(f"❌ Failed to load {file_path.name}: {e}")

    if not today_data:
        print(f"⚠️ No processed data found for {today_str}. Run your parsers first!")
        return

    print(f"\n🚀 Merging {len(today_data)} total records into single report...")

    final_output = dedup.deduplicate(today_data)

    # Naming convention verification
    final_filename = f"{datetime.now().strftime('%d-%m-%Y')}_single.json"
    
    print("\n--- 🏁 Final Integration Summary ---")
    print(f"Unique Global Indicators: {len(final_output)}")
    print(f"Output File: storage/final/{final_filename}")

    # Spot check for source merging
    multi_source = [i for i in final_output if len(i.get('sources', [])) > 1]
    if multi_source:
        print(f"✨ Found {len(multi_source)} indicators appearing in multiple feeds!")
        sample = multi_source[0]
        print(f"Sample: {sample['value']} | Sources: {sample['sources']}")

if __name__ == "__main__":
    run_final_merge()