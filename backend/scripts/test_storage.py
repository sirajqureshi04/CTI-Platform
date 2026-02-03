import sys
import argparse
import time
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.core.logger import CTILogger
from backend.core.config import get_settings
from backend.feeds.clearweb import (
    RansomwareLiveFeed,
    CISAKEVFeed,
    AlienVaultOTXFeed,
    MalpediaFeed
)

logger = CTILogger.get_logger(__name__)
settings = get_settings()

def store_raw_data(feed_name: str, data: Any) -> str:
    """
    Centralized logic to save raw data to your specific file structure.
    """
    # Map the internal feed key to your folder names
    folder_map = {
        "cisa_kev": "cisa",
        "alienvault_otx": "otx",
        "malpedia": "malpedia",
        "ransomware_live": "ransomware_live"
    }
    
    folder_name = folder_map.get(feed_name, feed_name)
    target_dir = PROJECT_ROOT / "storage" / "raw" / folder_name
    target_dir.mkdir(parents=True, exist_ok=True)
    
    # Save with a daily timestamp to prevent overwriting
    file_name = f"{datetime.now().strftime('%Y-%m-%d')}_raw.json"
    file_path = target_dir / file_name
    
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump({
            "metadata": {
                "ingested_at": datetime.now().isoformat(),
                "source": feed_name
            },
            "data": data
        }, f, indent=4)
        
    return str(file_path)

def test_feed_worker(feed_info: tuple) -> Dict[str, Any]:
    """
    Worker function: Now performs actual scraping and data persistence.
    """
    feed_key, (feed_class, config) = feed_info
    start_time = time.time()
    
    try:
        instance_config = {**settings.model_dump(), **config}
        feed = feed_class(config=instance_config)
        
        # 1. SCRAPE: Execute actual data collection
        # Assuming your feed classes have a fetch() or similar method
        raw_data = feed.fetch() 
        
        # 2. STORE: Persist to your raw storage files
        saved_path = store_raw_data(feed_key, raw_data)
        
        return {
            "feed_name": feed_key,
            "success": True,
            "items": len(raw_data) if isinstance(raw_data, list) else 1,
            "path": saved_path,
            "duration": round(time.time() - start_time, 2),
            "validation_passed": True
        }
    except Exception as e:
        logger.error(f"Ingestion failed for {feed_key}: {str(e)}")
        return {
            "feed_name": feed_key,
            "success": False,
            "error": str(e),
            "duration": round(time.time() - start_time, 2),
            "validation_passed": False,
            "items": 0
        }

def print_results(results: List[Dict[str, Any]]):
    """Enhanced results table showing storage paths."""
    print("\n" + "═"*100)
    print(f"{'FEED NAME':<20} | {'STATUS':<8} | {'ITEMS':<8} | {'TIME':<8} | {'STORAGE PATH'}")
    print("═"*100)
    
    for r in sorted(results, key=lambda x: x['success']):
        name = r.get("feed_name", "unknown")[:20]
        status = "✅ PASS" if r.get("success") else "❌ FAIL"
        items = r.get("items", 0)
        duration = f"{r.get('duration', 0)}s"
        path = r.get("path", "N/A")
        
        # Shorten path for display
        display_path = "..." + path[-35:] if path != "N/A" else "N/A"
        
        print(f"{name:<20} | {status:<8} | {items:<8} | {duration:<8} | {display_path}")

def main():
    parser = argparse.ArgumentParser(description="Parallel CTI Feed Ingestor")
    parser.add_argument("--feed", type=str, default="all")
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()

    all_feeds = {
        "ransomware_live": (RansomwareLiveFeed, {"bypass_cloudflare": True}),
        "cisa_kev": (CISAKEVFeed, {}),
        "alienvault_otx": (AlienVaultOTXFeed, {"api_key": settings.OTX_API_KEY}),
        "malpedia": (MalpediaFeed, {"api_key": settings.MALPEDIA_API_KEY})
    }

    selected = all_feeds if args.feed == "all" else {args.feed: all_feeds[args.feed]}
    print(f"\n🚀 Ingesting {len(selected)} feeds into Raw Storage...\n")
    
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_feed = {executor.submit(test_feed_worker, item): item[0] for item in selected.items()}
        for future in as_completed(future_to_feed):
            results.append(future.result())

    print_results(results)

if __name__ == "__main__":
    main()