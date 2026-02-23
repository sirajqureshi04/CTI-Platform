import time
import json
import os 
from pathlib import Path
from dotenv import load_dotenv # <--- ADDED: To ensure .env is read
from backend.enrichment.manager import EnrichmentManager
from backend.core.logger import CTILogger
from backend.core.config import settings

# Force load environment variables at the very start
load_dotenv()

logger = CTILogger.get_logger("TestRun")

def prepare_test_data():
    """Ensures there is at least one IOC file to enrich."""
    # Ensure base directory exists
    storage_dir = Path(settings.BASE_DIR) / "storage" / "final"
    storage_dir.mkdir(parents=True, exist_ok=True)
    
    test_file = storage_dir / "intel_report_TEST.json"
    
    if not test_file.exists():
        logger.info("📝 No test file found. Creating a sample IOC report...")
        # Note: Manager expects a dict with an "indicators" key
        sample_data = {
            "indicators": [
                {"type": "ipv4", "value": "8.8.8.8", "source": "test_script"},
                {"type": "domain", "value": "google.com", "source": "test_script"}
            ]
        }
        with open(test_file, "w") as f:
            json.dump(sample_data, f, indent=4)
    return test_file

def start_dry_run():
    logger.info("🚀 INITIALIZING ENRICHMENT TEST RUN...")
    
    # 1. Prepare Environment
    prepare_test_data()
    start_time = time.time()
    
    # 2. Initialize and Run Manager
    try:
        manager = EnrichmentManager()
        # FIXED: Changed manager.run() to manager.process_report() 
        # to match your manager.py code
        manager.process_report() 
    except Exception as e:
        logger.error(f"❌ Test Run Failed: {e}")
        import traceback
        logger.error(traceback.format_exc()) # Gives more detail on errors
        return

    duration = time.time() - start_time
    logger.info("--- TEST SUMMARY ---")
    logger.info(f"Total Time: {duration:.2f} seconds")
    
    if duration < 2: # Adjusted for local dry-run
        logger.warning("⚠️ Warning: Run was very fast. Check if data was actually processed.")

if __name__ == "__main__":
    start_dry_run()