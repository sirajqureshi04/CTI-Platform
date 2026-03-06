import json
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from backend.enrichment.manager import EnrichmentManager

FINAL_DIR = Path("storage/final")

DATE_PATTERN = re.compile(r"(\d{2}-\d{2}-\d{4})_single\.json")

MAX_WORKERS = 10


def get_files_to_process():
    files_to_process = []

    for file in FINAL_DIR.glob("*_single.json"):
        match = DATE_PATTERN.search(file.name)

        if not match:
            continue

        date = match.group(1)

        enriched_file = FINAL_DIR / f"{date}_enriched.json"

        if not enriched_file.exists():
            files_to_process.append((file, enriched_file, date))

    return files_to_process


def enrich_record(manager, item):
    try:
        return manager.process_item(item)
    except Exception:
        return item


def enrich_file(input_file: Path, output_file: Path, date: str):

    print(f"\n🚀 Enrichment started for {date}")

    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    total = len(data)

    print(f"📦 Records: {total}")
    print(f"⚡ Using {MAX_WORKERS} threads")

    manager = EnrichmentManager()

    enriched_data = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:

        futures = [executor.submit(enrich_record, manager, item) for item in data]

        for i, future in enumerate(as_completed(futures), start=1):

            enriched_data.append(future.result())

            if i % 1000 == 0:
                print(f"Processed {i}/{total}")

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(enriched_data, f, indent=4)

    print(f"✅ Saved → {output_file}")


def main():

    files = get_files_to_process()

    if not files:
        print("⚠ No new files found for enrichment")
        return

    for input_file, output_file, date in files:
        enrich_file(input_file, output_file, date)


if __name__ == "__main__":
    main()