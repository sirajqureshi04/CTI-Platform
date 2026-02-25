#!/usr/bin/env python3
import sys
import os
import json
from pathlib import Path
from datetime import datetime
import requests
from dotenv import load_dotenv

# Path Setup
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

load_dotenv()

try:
    from backend.feeds.darkweb.monitor import RansomwareMonitorFeed
    from backend.core.logger import CTILogger
except ImportError as e:
    print(f"❌ Import Error: {e}")
    sys.exit(1)

logger = CTILogger.get_logger("ScraperTest")

ENV_CONFIG = {
    "TOR_SOCKS_PROXY": os.getenv("TOR_SOCKS_PROXY", "socks5h://127.0.0.1:9150"),
    "sources": {
        "Everest": "http://ransomocmou6mnbquqz44ewosbkjk3o5qjsl3orawojexfook2j7esad.onion/",
        "LockBit": "http://lockbitapt2yfbt7lch7y7pt7gecgl7eyicbuilujocpoint.onion/"
    }
}

def check_tor_status():
    """Verify Tor Browser connectivity and external IP visibility."""
    proxy = ENV_CONFIG["TOR_SOCKS_PROXY"]
    try:
        proxies = {"http": proxy, "https": proxy}
        # Check Tor status
        response = requests.get("https://check.torproject.org/api/ip", proxies=proxies, timeout=15)
        data = response.json()
        return data.get("IsTor", False)
    except:
        return False

def run_diagnostic():
    print("\n" + "="*60)
    print(f"{'🕵️ DARK WEB SCRAPER DIAGNOSTIC (BROWSER MODE)':^60}")
    print("="*60)

    if not check_tor_status():
        print("❌ STATUS: Tor Browser NOT detected on port 9150.")
        print("💡 FIX: Ensure Tor Browser is OPEN and CONNECTED.")
        return
    
    print("🟢 STATUS: Tor Browser Connected. Starting scrape...")

    try:
        monitor = RansomwareMonitorFeed(config=ENV_CONFIG, logger=logger)
        results = monitor.fetch()
        
        standardized_iocs = []
        today_str = datetime.now().strftime("%Y-%m-%d")

        for source, info in results.get("detections", {}).items():
            sc = info.get("status_code")
            count = info.get("count", 0)
            
            status = "✅ ONLINE" if sc == 200 else "❌ OFFLINE/ERROR"
            print(f"\n[{status}] {source}")
            print(f"🔗 URL: {info.get('url')}")
            print(f"👥 Victims Found: {count}")
            
            if count > 0:
                for victim in info.get("victims", []):
                    standardized_iocs.append({
                        "ioc_value": f"{source.lower()}:{victim.lower().replace(' ', '_')}",
                        "ioc_type": "ransomware_victim",
                        "source": "ransomware_onion",
                        "metadata": {
                            "victim_name": victim,
                            "group": source,
                            "tags": ["darkweb", "onion", source.lower()]
                        }
                    })

        if standardized_iocs:
            processed_dir = PROJECT_ROOT / "storage" / "processed" / "darkweb"
            processed_dir.mkdir(parents=True, exist_ok=True)
            output_file = processed_dir / f"{today_str}_processed.json"
            
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(standardized_iocs, f, indent=4)
            print(f"\n📦 SAVED: {len(standardized_iocs)} records to {output_file}")
        else:
            print("\n⚠️ No data collected. If the site works in your browser but not here, try refreshing the circuit.")

    except Exception as e:
        logger.error(f"Test Failed: {e}", exc_info=True)

    print("\n" + "="*60)

if __name__ == "__main__":
    run_diagnostic()