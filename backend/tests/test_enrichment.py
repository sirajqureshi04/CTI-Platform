import time
import json
import os 
from pathlib import Path
from dotenv import load_dotenv
from backend.enrichment.manager import EnrichmentManager
from backend.core.logger import CTILogger
from backend.core.config import settings

# Force load environment variables at the very start
load_dotenv()

logger = CTILogger.get_logger("TestRun")

def prepare_test_data():
    """Ensures final_intelligence.json exists with fresh data for enrichment."""
    # Build path consistently with manager.py expectations
    # Project root is assumed to be the current working directory
    storage_dir = Path("storage/final")
    storage_dir.mkdir(parents=True, exist_ok=True)
    
    test_file = storage_dir / "final_intelligence.json"
    
    # FOR DRY RUNS: We overwrite to ensure there are no existing "enrichment" keys
    # This prevents the manager from skipping the indicators.
    logger.info("📝 Preparing fresh test data in storage/final/final_intelligence.json...")
    
    sample_data = {
        "metadata": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "scan_type": "dry_run"
        },
        "indicators": [
            {"type": "ipv4", "value": "1.1.1.1", "source": "cloudflare_dns"},
            {"type": "ipv4", "value": "8.8.8.8", "source": "google_dns"},
            {"type": "domain", "value": "malware-traffic-analysis.net", "source": "clearweb_feed"}
        ]
    }
    
    with open(test_file, "w") as f:
        json.dump(sample_data, f, indent=4)
        
    return test_file

def start_dry_run():
    logger.info("🚀 INITIALIZING ENRICHMENT TEST RUN...")
    
    # 1. Prepare Environment & Data
    test_file = prepare_test_data()
    
    if not test_file.exists():
        logger.error("❌ Failed to create test data file.")
        return

    start_time = time.time()
    
    # 2. Initialize and Run Manager
    try:
        manager = EnrichmentManager()
        # This will now find the file at storage/final/final_intelligence.json
        manager.process_report() 
    except Exception as e:
        logger.error(f"❌ Test Run Failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return

    duration = time.time() - start_time
    
    # 3. Verification Step: Check if the file was actually updated
    try:
        with open(test_file, 'r') as f:
            results = json.load(f)
            # Count how many have enrichment keys now
            enriched = [i for i in results.get("indicators", []) if "enrichment" in i]
            logger.info(f"✅ Verification: {len(enriched)}/{len(results['indicators'])} indicators enriched.")
    except Exception as e:
        logger.warning(f"⚠️ Could not verify results: {e}")

    logger.info("--- TEST SUMMARY ---")
    logger.info(f"Total Time: {duration:.2f} seconds")
    
    if duration < 0.1: 
        logger.warning("⚠️ Warning: Run was near-instant. Check logs for path or API errors.")

if __name__ == "__main__":
    start_dry_run()