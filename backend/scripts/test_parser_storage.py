import os
import json
import sys

# 1. FIXING PATHS: Ensure the script can see the 'backend' folder
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from backend.parsers.factory import ParserFactory
    from backend.models.indicator import ProcessedIndicator
    print("✅ Imports successful.")
except ImportError as e:
    print(f"❌ Import Error: {e}")
    sys.exit(1)

# Define paths
RAW_DIR = "storage/raw"
PARSED_DIR = "storage/parsed"

def run_storage_test():
    print(f"🚀 Scanning {RAW_DIR} for data...")
    
    # Ensure the parsed directory exists
    os.makedirs(PARSED_DIR, exist_ok=True)

    if not os.path.exists(RAW_DIR):
        print(f"⚠️ Warning: {RAW_DIR} folder not found. Check your paths!")
        return

    for feed_name in os.listdir(RAW_DIR):
        feed_path = os.path.join(RAW_DIR, feed_name)
        if not os.path.isdir(feed_path): continue

        print(f"\n📂 Processing Feed: {feed_name}")
        parser = ParserFactory.get_parser(feed_name)

        for filename in os.listdir(feed_path):
            if filename.endswith(".json"):
                print(f"   📄 Reading {filename}...")
                file_full_path = os.path.join(feed_path, filename)

                try:
                    # Parse data
                    raw_data = parser(file_full_path)
                    
                    # Normalize and save
                    processed_results = []
                    for item in raw_data:
                        # Validation via your Model
                        valid_ind = ProcessedIndicator(**item)
                        processed_results.append(valid_ind.model_dump())

                    # SAVE BACK TO STORAGE/PARSED
                    output_filename = f"parsed_{filename}"
                    output_path = os.path.join(PARSED_DIR, feed_name)
                    os.makedirs(output_path, exist_ok=True)
                    
                    with open(os.path.join(output_path, output_filename), 'w') as f:
                        json.dump(processed_results, f, indent=4, default=str)
                    
                    print(f"   ✔️ Saved {len(processed_results)} indicators to {output_path}")

                except Exception as e:
                    print(f"   🔥 Error processing {filename}: {e}")

# IMPORTANT: This block is required to make the script run!
if __name__ == "__main__":
    print("--- TEST START ---")
    run_storage_test()
    print("\n--- TEST END ---")