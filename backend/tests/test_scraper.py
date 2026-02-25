#!/usr/bin/env python3
import sys
import os
import json
from pathlib import Path
from datetime import datetime
import requests
from dotenv import load_dotenv

# 1. Path Setup
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Load .env before importing monitor
load_dotenv()

try:
    from backend.feeds.darkweb.monitor import RansomwareMonitorFeed
    from backend.core.logger import CTILogger
except ImportError as e:
    print(f"❌ Import Error: {e}")
    sys.exit(1)

logger = CTILogger.get_logger("ScraperTest")

# 2. Dynamic Configuration: Updated for Tor Browser (9150)
# We prioritize .env, then 9150 (Browser), then fallback to 9050 (Service)
DEFAULT_PROXY = os.getenv("TOR_SOCKS_PROXY", "socks5h://127.0.0.1:9150")

ENV_CONFIG = {
    "TOR_SOCKS_PROXY": DEFAULT_PROXY,
    "timeout": int(os.getenv("SCRAPER_TIMEOUT", 90)),
    "max_retries": int(os.getenv("SCRAPER_RETRIES", 5)),
    "sources": {
        "Everest": "http://ransomocmou6mnbquqz44ewosbkjk3o5qjsl3orawojexfook2j7esad.onion/",
        "LockBit": "http://lockbitapt2yfbt7lch7y7pt7gecgl7eyicbuilujocpoint.onion/"
    }
}

def check_tor_status():
    """Verify Tor connectivity and anonymity via Tor Browser port."""
    proxy_to_check = ENV_CONFIG["TOR_SOCKS_PROXY"]
    try:
        proxies = {"http": proxy_to_check, "https": proxy_to_check}
        # Short timeout for the check to see if the port is even open
        response = requests.get("https://check.torproject.org", proxies=proxies, timeout=10)
        return "Congratulations" in response.text
    except Exception as e:
        logger.debug(f"Tor check failed on {proxy_to_check}: {e}")
        return False

def run_diagnostic():
    logger.info("Starting Dark Web Scraper Diagnostic (Tor Browser Mode)...")
    
    # Check if Tor Browser is actually open
    if not check_tor_status():
        print("\n" + "!"*60)
        print("❌ ERROR: Tor Proxy Offline.")
        print(f"Target Port: {ENV_CONFIG['TOR_SOCKS_PROXY']}")
        print("Steps to fix:")
        print("1. Open the Tor Browser.")
        print("2. Ensure you have clicked 'Connect' inside the browser.")
        print("3. Verify the browser is working by visiting a website.")
        print("!"*60 + "\n")
        return

    try:
        # Initialize with merged config
        monitor = RansomwareMonitorFeed(config=ENV_CONFIG, logger=logger)
        print(f"\n📡 Connected! Using Proxy: {ENV_CONFIG['TOR_SOCKS_PROXY']}")
        print("🕵️  Scraping Onion Sites (this may take a minute)...")
        
        results = monitor.fetch()
        
        print("\n" + "="*60)
        print(f"{'📊 SCRAPER TEST RESULTS':^60}")
        print("="*60)
        
        standardized_iocs = []
        today_str = datetime.now().strftime("%Y-%m-%d")

        for source, info in results.get("detections", {}).items():
            count = info.get("count", 0)
            sc = info.get("status_code")
            
            status = "🟢 ONLINE" if count > 0 else "🟠 NO DATA"
            if sc != 200: status = f"🔴 FAILED ({sc})"

            print(f"\n[{status}] {source}")
            print(f"🔗 URL: {info.get('url')}")
            print(f"👥 Victims Found: {count}")
            
            if count > 0:
                print("📝 Sample Victims:")
                for v in info.get("victims", [])[:3]:
                    print(f"   - {v}")
                
                for victim in info.get("victims", []):
                    standardized_iocs.append({
                        "ioc_value": f"{source.lower()}:{victim.lower().replace(' ', '_')}",
                        "ioc_type": "ransomware_victim",
                        "source": "ransomware_onion",
                        "metadata": {
                            "victim_name": victim,
                            "group": source,
                            "leak_url": info.get("url"),
                            "tags": ["darkweb", "onion", source.lower()]
                        }
                    })

        # Save Logic
        if standardized_iocs:
            processed_dir = PROJECT_ROOT / "storage" / "processed" / "darkweb"
            processed_dir.mkdir(parents=True, exist_ok=True)
            
            output_file = processed_dir / f"{today_str}_processed.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(standardized_iocs, f, indent=4)
            
            print("\n" + "-"*60)
            print(f"📦 SUCCESS: {len(standardized_iocs)} records saved to:")
            print(f"📂 {output_file}")
            print("-" * 60)
        else:
            print("\n⚠️ No victims were parsed. Check if the onion sites are up.")

        print("\n" + "="*60)
        
    except Exception as e:
        logger.error(f"Test Failed: {e}", exc_info=True)

if __name__ == "__main__":
    run_diagnostic()