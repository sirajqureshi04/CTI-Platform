import sys
import argparse
import time
from pathlib import Path
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

def test_feed_worker(feed_info: tuple) -> Dict[str, Any]:
    """
    Worker function for parallel execution of feed dry runs.
    """
    feed_key, (feed_class, config) = feed_info
    start_time = time.time()
    
    try:
        # Merge global .env settings with specific test overrides
        instance_config = {**settings.model_dump(), **config}
        feed = feed_class(config=instance_config)
        
        # Execute the refined dry_run (No 404s due to capability checking)
        result = feed.dry_run()
        result["duration"] = round(time.time() - start_time, 2)
        return result
    except Exception as e:
        return {
            "feed_name": feed_key,
            "success": False,
            "error": str(e),
            "duration": round(time.time() - start_time, 2),
            "validation_passed": False,
            "data_summary": {}
        }

def print_results(results: List[Dict[str, Any]]):
    """Print high-visibility optimized results table."""
    print("\n" + "═"*85)
    print(f"{'FEED NAME':<25} | {'STATUS':<8} | {'ITEMS':<8} | {'TIME':<8} | {'VALIDATION'}")
    print("═"*85)
    
    # Sort results to show failures at the top
    for r in sorted(results, key=lambda x: x['success']):
        name = r.get("feed_name", "unknown")[:25]
        status = "✅ PASS" if r.get("success") else "❌ FAIL"
        items = r.get("data_summary", {}).get("total_items", 0)
        duration = f"{r.get('duration', 0)}s"
        val = "✓" if r.get("validation_passed") else "✗"
        
        print(f"{name:<25} | {status:<8} | {items:<8} | {duration:<8} | {val}")
        
        if not r.get("success"):
            print(f"   └─ ⚠️ Error: {r.get('error')}")

def main():
    parser = argparse.ArgumentParser(description="Parallel CTI Feed Tester")
    parser.add_argument("--feed", type=str, default="all")
    parser.add_argument("--workers", type=int, default=4, help="Parallel threads")
    args = parser.parse_args()

    # Integrated feed definitions with specific requirements
    all_feeds = {
        "ransomware_live": (RansomwareLiveFeed, {"bypass_cloudflare": True}),
        "cisa_kev": (CISAKEVFeed, {}),
        "alienvault_otx": (AlienVaultOTXFeed, {"api_key": settings.OTX_API_KEY}),
        "malpedia": (MalpediaFeed, {"api_key": settings.MALPEDIA_API_KEY})
    }

    selected = all_feeds if args.feed == "all" else {args.feed: all_feeds[args.feed]}
    
    print(f"\n🚀 Launching {len(selected)} tests across {args.workers} workers...\n")
    
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        # Submit all feeds to the thread pool for simultaneous testing
        future_to_feed = {executor.submit(test_feed_worker, item): item[0] for item in selected.items()}
        
        for future in as_completed(future_to_feed):
            results.append(future.result())

    print_results(results)
    
    return 0 if all(r.get("success") for r in results) else 1

if __name__ == "__main__":
    main()