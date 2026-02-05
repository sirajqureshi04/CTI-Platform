#!/usr/bin/env python3
import sys
from pathlib import Path

# Fix pathing so 'backend' is discoverable
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.core.logger import CTILogger
from backend.core.pipeline import CTIPipeline
from backend.feeds.clearweb import (
    CISAKEVFeed, AlienVaultOTXFeed, 
    MalpediaFeed, URLhausFeed
)
# NEW: Import the refined Dark Web Monitor
from backend.feeds.darkweb.monitor import RansomwareMonitorFeed

logger = CTILogger.get_logger(__name__)

def main():
    logger.info("--- Starting Hybrid CTI Pipeline Driver ---")
    
    # Example Dark Web Config (should ideally move to a config.yaml later)
    DARK_WEB_CONFIG = {
        "sources": {
            "Everest": "http://ransomocmou6mnbquqz44ewosbkjk3o5qjsl3orawojexfook2j7esad.onion/",
            "LockBit_Mirror": "http://lockbitapt2yfbt7lch7y7pt7gecgl7eyicbuilujocpoint.onion/"
        },
        "timeout": 90,
        "max_retries": 5
    }

    try:
        # Initialize Engine (Handles DAOs and routing)
        pipeline = CTIPipeline()
        
        # Define Feed List (Mixing Clearweb and Darkweb)
        feeds = [
            # 1. Dark Web Monitor (uses TorHTTPClient internally)
            RansomwareMonitorFeed(config=DARK_WEB_CONFIG),
            
            # 2. Clearweb Feeds (use SecureHTTPClient)
            CISAKEVFeed(),
            AlienVaultOTXFeed(),
            MalpediaFeed(),
            URLhausFeed()
        ]
        
        # Run and Capture Results
        # pipeline.run_all_feeds will now handle the logic branching 
        # for ransomware victims vs standard IOCs.
        summary = pipeline.run_all_feeds(feeds)
        
        # Visual Summary for CLI
        print("\n" + "═"*40)
        print(f"  CTI RUN SUMMARY | {summary.get('execution_time', 'N/A')}")
        print("═"*40)
        
        total = len(summary['results'])
        successful = sum(1 for r in summary['results'] if r["success"])
        
        for res in summary['results']:
            status = "✅" if res['success'] else "❌"
            feed_name = res['feed_name'].ljust(20)
            
            if res['success']:
                detail = f"{res.get('count', 0)} {res.get('type', 'Items')}"
            else:
                detail = f"ERROR: {str(res.get('error'))[:40]}..."
                
            print(f"{status} {feed_name}: {detail}")
            
        print("═"*40)
        print(f"  OVERALL: {successful}/{total} Feeds Completed")
        print("═"*40 + "\n")
        
        return 0
    except Exception as e:
        logger.critical(f"Driver failure: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())