import json
import os
import sys
from datetime import datetime

# Ensure the backend directory is in the path for absolute imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from backend.enrichment.manager import EnrichmentManager

class EnrichmentTester:
    def __init__(self, input_file="single.json", output_file="enriched_output.json"):
        self.input_file = input_file
        self.output_file = output_file
        self.manager = EnrichmentManager()

    def load_data(self):
        if not os.path.exists(self.input_file):
            print(f"❌ Error: {self.input_file} not found. Please ensure your feed data is in the root.")
            return None
        with open(self.input_file, 'r') as f:
            return json.load(f)

    def save_data(self, data):
        with open(self.output_file, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"✅ Success: Enriched data saved to {self.output_file}")

    def run(self):
        raw_data = self.load_data()
        if not raw_data:
            return

        print(f"🚀 Starting Enrichment Pipeline at {datetime.now().strftime('%H:%M:%S')}")
        print(f"📊 Processing {len(raw_data)} items from {self.input_file}...")
        
        enriched_results = []
        
        for index, item in enumerate(raw_data):
            val = item.get("value", "Unknown")
            type_ = item.get("type", "Unknown")
            
            print(f"  [{index+1}/{len(raw_data)}] Enriching {type_}: {val}...", end="\r")
            
            # Use the manager to route to the correct provider
            enriched_item = self.manager.process_item(item)
            enriched_results.append(enriched_item)

        print("\n✨ All items processed.")
        self.save_data(enriched_results)

if __name__ == "__main__":
    tester = EnrichmentTester()
    tester.run()