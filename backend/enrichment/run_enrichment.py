import json
import re
from pathlib import Path
from datetime import datetime

from backend.enrichment.manager import EnrichmentManager


class EnrichmentRunner:

    def __init__(self):

        self.project_root = Path(__file__).resolve().parents[2]

        # storage/final directory
        self.final_storage = self.project_root / "storage" / "final"

        self.manager = EnrichmentManager()

        # Regex pattern to detect date based files
        self.pattern = re.compile(r"(\d{2}-\d{2}-\d{4})_single\.json")

    def get_target_files(self):
        """
        Finds all single.json files and returns only the ones
        that do not already have enriched outputs.
        """

        targets = []

        for file in self.final_storage.glob("*_single.json"):

            match = self.pattern.match(file.name)

            if not match:
                continue

            date_part = match.group(1)

            enriched_file = self.final_storage / f"{date_part}_enriched.json"

            if enriched_file.exists():
                continue

            targets.append((file, enriched_file, date_part))

        return targets

    def enrich_file(self, input_file, output_file, date):

        print(f"\n🚀 Enrichment started for {date}")

        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        print(f"📦 Processing {len(data)} records")

        enriched_data = []

        for item in data:
            enriched_item = self.manager.process_item(item)
            enriched_data.append(enriched_item)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(enriched_data, f, indent=4)

        print(f"✅ Enriched file created → {output_file.name}")

    def run(self):

        targets = self.get_target_files()

        if not targets:
            print("⚠️ No new files found for enrichment.")
            return

        for input_file, output_file, date in targets:
            self.enrich_file(input_file, output_file, date)

        print("\n🎯 Enrichment pipeline finished")


if __name__ == "__main__":
    runner = EnrichmentRunner()
    runner.run()