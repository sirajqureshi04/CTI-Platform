#!/usr/bin/env python3
import sys
from pathlib import Path

# Fix pathing so 'backend' is discoverable
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.core.logger import CTILogger
from backend.core.pipeline import CTIPipeline
from backend.feeds.clearweb import (
    RansomwareLiveFeed, CISAKEVFeed, AlienVaultOTXFeed, 
    MalpediaFeed, FeodoTrackerFeed, URLhausFeed
)

logger = CTILogger.get_logger(__name__)

def main():
    logger.info("--- Starting CTI Pipeline Driver ---")
    
    try:
        # Initialize Engine
        pipeline = CTIPipeline()
        
        # Define Feed List
        feeds = [
            RansomwareLiveFeed(),
            CISAKEVFeed(),
            AlienVaultOTXFeed(),
            MalpediaFeed(),
            URLhausFeed()
        ]
        
        # Run and Capture Results
        summary = pipeline.run_all_feeds(feeds)
        
        # Visual Summary
        print("\n" + "="*30)
        print(f"RUN COMPLETE: {summary['successful']}/{summary['total']} SUCCESS")
        for res in summary['results']:
            status = "✓" if res['success'] else "✗"
            detail = f"{res.get('count', 0)} {res.get('type', '')}" if res['success'] else res.get('error')
            print(f"{status} {res['feed_name']}: {detail}")
        print("="*30 + "\n")
        
        return 0
    except Exception as e:
        logger.critical(f"Driver failure: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())

