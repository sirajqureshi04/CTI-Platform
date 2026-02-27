#!/usr/bin/env python3
import sys
import os
import json
import socket
import socks
import requests
from pathlib import Path
from datetime import datetime
import time
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

# Fixed URLs - These match the ones in monitor.py
ENV_CONFIG = {
    "TOR_SOCKS_PROXY": os.getenv("TOR_SOCKS_PROXY", "socks5h://127.0.0.1:9150"),
    "sources": {
        "Everest": "http://ransomocmou6mnbquqz44ewosbkjk3o5qjsl3orawojexfook2j7esad.onion/",
        "LockBit": "http://lockbitapt2yfbt7lch7y7pt7gecgl7eyicbuilujocpoint.onion/"
    }
}

def check_tor_service():
    """Check if Tor service is running on port 9150."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', 9150))
    sock.close()
    return result == 0

def test_socks_proxy():
    """Test if SOCKS proxy is responding."""
    try:
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, "127.0.0.1", 9150)
        s.settimeout(10)
        s.connect(("check.torproject.org", 80))
        s.send(b"GET / HTTP/1.0\r\nHost: check.torproject.org\r\n\r\n")
        response = s.recv(1024)
        s.close()
        return True, "SOCKS proxy is working"
    except Exception as e:
        return False, f"SOCKS proxy test failed: {e}"

def check_tor_status():
    """Enhanced Tor connectivity check with multiple tests."""
    proxy = ENV_CONFIG["TOR_SOCKS_PROXY"]
    
    print("\n🔍 Checking Tor connectivity...")
    
    # Test 1: Check if port is open
    if not check_tor_service():
        print("❌ Port 9150 is not accessible")
        print("   Make sure Tor Browser is running")
        return False
    print("✅ Port 9150 is open")
    
    # Test 2: Test SOCKS proxy
    socks_ok, socks_msg = test_socks_proxy()
    if not socks_ok:
        print(f"❌ {socks_msg}")
        return False
    print(f"✅ {socks_msg}")
    
    # Test 3: Check Tor network connection
    try:
        proxies = {"http": proxy, "https": proxy}
        response = requests.get(
            "https://check.torproject.org/api/ip", 
            proxies=proxies, 
            timeout=30
        )
        data = response.json()
        
        if data.get("IsTor", False):
            ip = data.get("IP", "unknown")
            print(f"✅ Connected to Tor network - Exit IP: {ip}")
            return True
        else:
            print("❌ Connected but not using Tor")
            return False
            
    except requests.exceptions.ConnectionError as e:
        print(f"❌ Cannot connect to Tor proxy: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_onion_connectivity():
    """Test direct connection to onion sites."""
    proxy = ENV_CONFIG["TOR_SOCKS_PROXY"]
    proxies = {"http": proxy, "https": proxy}
    
    # Test with DuckDuckGo's onion site (known to be reliable)
    test_onion = "http://3g2upl4pq6kufc4m.onion/"
    
    print("\n🌐 Testing onion site connectivity...")
    
    try:
        response = requests.get(
            test_onion, 
            proxies=proxies, 
            timeout=60,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
            }
        )
        print(f"✅ Successfully connected to test onion site")
        print(f"   Status code: {response.status_code}")
        print(f"   Response size: {len(response.text)} bytes")
        return True
    except requests.exceptions.Timeout:
        print("❌ Timeout connecting to onion site")
        print("   Tor might be slow or the site might be down")
        return False
    except Exception as e:
        print(f"❌ Cannot access onion sites: {e}")
        return False

def run_diagnostic():
    """Main diagnostic function."""
    print("\n" + "="*70)
    print(f"{'🕵️ DARK WEB SCRAPER DIAGNOSTIC (TOR BROWSER MODE)':^70}")
    print("="*70)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)

    # Step 1: Check Tor connectivity
    tor_status = check_tor_status()
    if not tor_status:
        print("\n💡 TROUBLESHOOTING STEPS:")
        print("   1. Start Tor Browser")
        print("   2. Wait for it to connect to the Tor network (green onion icon)")
        print("   3. Keep Tor Browser running in the background")
        print("   4. Verify proxy settings in Tor Browser (default: 127.0.0.1:9150)")
        print("\n   To test manually, run: curl --socks5-hostname 127.0.0.1:9150 https://check.torproject.org/api/ip")
        return
    
    # Step 2: Test onion site access
    onion_status = test_onion_connectivity()
    if not onion_status:
        print("\n⚠️  Tor is working but can't access onion sites")
        print("   This might mean:")
        print("   - Tor Browser needs to be restarted")
        print("   - Network is blocking Tor")
        print("   - Try refreshing Tor circuit")
        return

    print("\n🟢 All systems go. Starting scrape...")
    print("="*70)

    try:
        # Create monitor instance
        monitor = RansomwareMonitorFeed(config=ENV_CONFIG, logger=logger)
        
        # Run the scraper
        start_time = time.time()
        results = monitor.fetch()
        elapsed_time = time.time() - start_time
        
        print(f"\n⏱️  Scraping completed in {elapsed_time:.2f} seconds")
        print("\n" + "="*70)
        print("📊 SCRAPER TEST RESULTS")
        print("="*70)
        
        standardized_iocs = []
        today_str = datetime.now().strftime("%Y-%m-%d")

        for source, info in results.get("detections", {}).items():
            sc = info.get("status_code")
            count = info.get("count", 0)
            url = info.get("url", "N/A")
            
            # Determine status emoji
            if sc == 200:
                status = "✅ ONLINE"
            elif sc == "TOR_NOT_CONNECTED":
                status = "🔴 TOR OFFLINE"
            else:
                status = "❌ FAILED"
            
            print(f"\n{status} {source}")
            print(f"🔗 URL: {url[:80]}...")  # Truncate long URLs
            print(f"👥 Victims Found: {count}")
            
            if count > 0:
                print(f"📋 Victims: {', '.join(info.get('victims', [])[:5])}")
                if len(info.get('victims', [])) > 5:
                    print(f"   ... and {len(info.get('victims', [])) - 5} more")
                
                # Prepare for JSON export
                for victim in info.get("victims", []):
                    standardized_iocs.append({
                        "ioc_value": f"{source.lower()}:{victim.lower().replace(' ', '_')}",
                        "ioc_type": "ransomware_victim",
                        "source": "ransomware_onion",
                        "timestamp": today_str,
                        "metadata": {
                            "victim_name": victim,
                            "group": source,
                            "url": url,
                            "tags": ["darkweb", "onion", source.lower()]
                        }
                    })

        # Save results if any victims found
        if standardized_iocs:
            processed_dir = PROJECT_ROOT / "storage" / "processed" / "darkweb"
            processed_dir.mkdir(parents=True, exist_ok=True)
            output_file = processed_dir / f"{today_str}_processed.json"
            
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(standardized_iocs, f, indent=4)
            print(f"\n📦 SAVED: {len(standardized_iocs)} records to {output_file}")
        else:
            print("\n⚠️  No victims were parsed.")
            print("   Possible reasons:")
            print("   • Onion sites might be temporarily down")
            print("   • Site structure may have changed")
            print("   • Tor circuit might need refreshing")
            print("   • Try accessing the URLs manually in Tor Browser")

    except Exception as e:
        logger.error(f"Test Failed: {e}", exc_info=True)
        print(f"\n❌ ERROR: {e}")
        print("\n💡 Check the log file for more details:")
        print(f"   {PROJECT_ROOT}/logs/cti_platform.log")

    print("\n" + "="*70)

if __name__ == "__main__":
    run_diagnostic()