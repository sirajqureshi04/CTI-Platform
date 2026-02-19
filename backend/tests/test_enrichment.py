import time
from backend.enrichment.manager import EnrichmentManager
from backend.core.logger import CTILogger

logger = CTILogger.get_logger("TestRun")

def start_dry_run():
    logger.info("🛠️ INITIALIZING ENRICHMENT TEST RUN...")
    start_time = time.time()
    
    # 1. Initialize the Manager
    # Note: Ensure your manager.py _get_latest_report logic picks up the TEST file!
    manager = EnrichmentManager()
    
    # 2. Execute
    try:
        manager.run()
    except Exception as e:
        logger.error(f"❌ Test Run Failed: {e}")
        return

    end_time = time.time()
    duration = end_time - start_time
    
    logger.info("--- TEST SUMMARY ---")
    logger.info(f"Total Time: {duration:.2f} seconds")
    logger.info("Check storage/final/intel_report_TEST.json for results.")
    
    if duration < 30:
        logger.warning("⚠️ Warning: Run was very fast. Check if Rate Limiter (15s sleep) is working!")

if __name__ == "__main__":
    start_dry_run()