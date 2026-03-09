import json
import re
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from backend.enrichment.manager import EnrichmentManager

FINAL_DIR = Path("storage/final")

DATE_PATTERN = re.compile(r"(\d{2}-\d{2}-\d{4})_single\.json")

# better thread scaling for I/O workloads
MAX_WORKERS = min(32, os.cpu_count() * 5)

CHUNK_SIZE = 1000


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


def enrich_record(item):
    """
    Thread-safe enrichment wrapper
    """
    manager = EnrichmentManager()

    try:
        return manager.process_item(item)
    except Exception:
        return item


def process_chunk(chunk):

    results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:

        futures = [executor.submit(enrich_record, item) for item in chunk]

        for future in as_completed(futures):
            results.append(future.result())

    return results


def enrich_file(input_file: Path, output_file: Path, date: str):

    print(f"\n🚀 Enrichment started for {date}")

    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    total = len(data)

    print(f"📦 Records: {total}")
    print(f"⚡ Threads: {MAX_WORKERS}")

    enriched_data = []

    for i in range(0, total, CHUNK_SIZE):

        chunk = data[i:i + CHUNK_SIZE]

        results = process_chunk(chunk)

        enriched_data.extend(results)

        print(f"Processed {min(i+CHUNK_SIZE,total)}/{total}")

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(enriched_data, f)   # removed indent (much faster)

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