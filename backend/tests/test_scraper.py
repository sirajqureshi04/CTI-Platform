#!/usr/bin/env python3
import sys
import json
from pathlib import Path
import requests

# 1. Path Fix: Ensure the script can see the 'backend' package
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from backend.feeds.darkweb.monitor import RansomwareMonitorFeed
    from backend.core.logger import CTILogger
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print(f"DEBUG: Search Path: {sys.path[0]}")
    sys.exit(1)

logger = CTILogger.get_logger("ScraperTest")

# 2. Configuration (Matches refined monitor.py)
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
    "max_retries": 5,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
}

def check_dependencies():
    """Verify 'requests[socks]' is installed."""
    try:
        import socks
        return True
    except ImportError:
        logger.error("❌ Missing SOCKS support. Run: pip install 'requests[socks]'")
        return False

def check_tor_status():
    """Diagnostic check to ensure Tor is reachable and resolving DNS."""
    try:
        # check.torproject.org is the gold standard for verifying SOCKS5h
        test_url = "https://check.torproject.org"
        response = requests.get(test_url, proxies=TEST_CONFIG["proxies"], timeout=20)
        if "Congratulations" in response.text:
            logger.info("✅ Tor Connection Verified (SOCKS5h active).")
            return True
    except Exception as e:
        logger.debug(f"Tor check failed: {e}")
    return False

def run_diagnostic():
    logger.info("Starting Dark Web Scraper Diagnostic...")
    
    if not check_dependencies():
        return

    if not check_tor_status():
        logger.error("❌ Tor Proxy Offline or DNS Leak detected. Ensure Tor service is on port 9050.")
        print("\n❌ TOR SERVICE NOT FOUND. Ensure 'tor' is running.")
        return

    try:
        monitor = RansomwareMonitorFeed(config=TEST_CONFIG)
        print("\n📡 Connecting to Tor Network and Fetching Feeds...")
        results = monitor.fetch()
        
        print("\n" + "="*60)
        print(f"{'📊 SCRAPER TEST RESULTS':^60}")
        print("="*60)
        
        detections = results.get("detections", {})
        if not detections:
            print("⚠️ No data returned. Check logs for connection errors.")
            return

        for source, info in detections.items():
            count = info.get("count", 0)
            status_code = info.get("status_code")
            
            # Determine status label
            if status_code == "CONNECTION_ERROR":
                status = "🔴 CONNECTION FAILED"
            elif status_code == 200 and count > 0:
                status = "🟢 ONLINE (DATA FOUND)"
            elif status_code == 200 and count == 0:
                status = "🟠 REACHABLE (NO DATA/PARSING FAIL)"
            else:
                status = f"🔴 OFFLINE (HTTP {status_code})"

            print(f"\n[{status}] {source}")
            print(f"🔗 URL: {info.get('url')}")
            print(f"👥 Victims Found: {count}")
            
            if count > 0:
                print("📝 Sample Victims:")
                # The refined monitor returns a list of strings
                for v in info.get("victims", [])[:5]:
                    print(f"   - {v}")

        print("\n" + "="*60)
        
    except Exception as e:
        logger.error(f"Test Failed: {e}", exc_info=True)
        print(f"\n❌ ERROR: {e}")

if __name__ == "__main__":
    run_diagnostic()