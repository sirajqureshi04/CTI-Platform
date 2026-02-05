import sys
import json
from pathlib import Path

# 1. Path Fix: Ensure the script can see the 'backend' package
# This moves up two levels to the project root
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.feeds.darkweb.monitor import RansomwareMonitorFeed
from backend.core.logger import CTILogger

logger = CTILogger.get_logger("ScraperTest")

# 2. Test Configuration
TEST_CONFIG = {
    "sources": {
        "Everest": "http://ransomocmou6mnbquqz44ewosbkjk3o5qjsl3orawojexfook2j7esad.onion/",
        # Add a secondary one for variety
        "LockBit": "http://lockbitapt2yfbt7lch7y7pt7gecgl7eyicbuilujocpoint.onion/"
    },
    "timeout": 90,
    "max_retries": 3
}

def run_diagnostic():
    logger.info("Starting Dark Web Scraper Diagnostic...")
    
    try:
        # Initialize the monitor
        monitor = RansomwareMonitorFeed(config=TEST_CONFIG)
        
        # Execute the fetch logic
        print("\n📡 Connecting to Tor Network...")
        results = monitor.fetch()
        
        # Display Findings
        print("\n" + "="*50)
        print("📊 SCRAPER TEST RESULTS")
        print("="*50)
        
        detections = results.get("detections", {})
        if not detections:
            print("⚠️ No data returned. Check if Tor is running (Port 9050).")
            return

        for source, info in detections.items():
            count = info.get("count", 0)
            status = "🟢 ONLINE" if count > 0 else "🔴 NO DATA"
            print(f"\n[{status}] Source: {source}")
            print(f"🔗 URL: {info.get('url')}")
            print(f"👥 Victims Found: {count}")
            
            if count > 0:
                print("📝 Sample Victims:")
                for v in info.get("victims", [])[:3]: # Show first 3
                    print(f"   - {v['title']}")
                    
        print("\n" + "="*50)
        
    except Exception as e:
        logger.error(f"Test Failed: {e}", exc_info=True)

if __name__ == "__main__":
    run_diagnostic()