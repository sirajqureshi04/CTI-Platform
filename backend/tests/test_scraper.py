#!/usr/bin/env python3
import sys
import json
from pathlib import Path
import requests

# 1. Path Fix: Ensure the script can see the 'backend' package
# This moves up to the project root relative to this script's location
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Attempt imports after path fix
try:
    from backend.feeds.darkweb.monitor import RansomwareMonitorFeed
    from backend.core.logger import CTILogger
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print(f"DEBUG: Search Path: {sys.path[0]}")
    sys.exit(1)

logger = CTILogger.get_logger("ScraperTest")

# 2. Enhanced Test Configuration
# Note: 'socks5h' forces DNS resolution to happen over Tor (prevents leaks/failures)
TEST_CONFIG = {
    "proxies": {
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050"
    },
    "sources": {
        "Everest": "http://ransomocmou6mnbquqz44ewosbkjk3o5qjsl3orawojexfook2j7esad.onion/",
        "LockBit": "http://lockbitapt2yfbt7lch7y7pt7gecgl7eyicbuilujocpoint.onion/"
    },
    "timeout": 90,
    "max_retries": 3,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
}

def check_tor_status():
    """Diagnostic check to ensure Tor is reachable before starting."""
    try:
        test_url = "http://check.torproject.org"
        proxies = TEST_CONFIG["proxies"]
        response = requests.get(test_url, proxies=proxies, timeout=15)
        if "Congratulations" in response.text:
            logger.info("✅ Tor Connection Verified: Traffic is anonymized.")
            return True
    except Exception:
        pass
    return False

def run_diagnostic():
    logger.info("Starting Dark Web Scraper Diagnostic...")
    
    if not check_tor_status():
        logger.error("❌ Tor Proxy Offline. Ensure Tor service is running on port 9050.")
        print("\n❌ TOR SERVICE NOT FOUND. Run 'brew services start tor' or 'sudo service tor start'.")
        return

    try:
        # Initialize the monitor with our explicit config
        monitor = RansomwareMonitorFeed(config=TEST_CONFIG)
        
        print("\n📡 Connecting to Tor Network and Fetching Feeds...")
        results = monitor.fetch()
        
        print("\n" + "="*50)
        print("📊 SCRAPER TEST RESULTS")
        print("="*50)
        
        detections = results.get("detections", {})
        if not detections:
            print("⚠️ No data returned from onion sources. They may be temporarily offline.")
            return

        for source, info in detections.items():
            count = info.get("count", 0)
            status = "🟢 ONLINE" if count > 0 else "🟠 REACHABLE (NO DATA)"
            
            # If status_code is returned in your Feed object, check it
            if info.get("status_code") and info["status_code"] != 200:
                status = f"🔴 OFFLINE ({info['status_code']})"

            print(f"\n[{status}] Source: {source}")
            print(f"🔗 URL: {info.get('url')}")
            print(f"👥 Victims Found: {count}")
            
            if count > 0:
                print("📝 Sample Victims:")
                for v in info.get("victims", [])[:3]:
                    print(f"   - {v.get('title', 'N/A')}")

        print("\n" + "="*50)
        
    except Exception as e:
        logger.error(f"Test Failed: {e}", exc_info=True)
        print(f"\n❌ ERROR: {e}")

if __name__ == "__main__":
    run_diagnostic()