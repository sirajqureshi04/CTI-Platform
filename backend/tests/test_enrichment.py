import sys
import os
from datetime import datetime

# Ensure project root is in the path to recognize 'backend' as a package
project_root = os.path.abspath(os.path.dirname(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from backend.core.config import settings
from backend.enrichment.run_enrichment import EnrichmentRunner
from backend.processors.deduplicator import Deduplicator
from backend.core.logger import CTILogger
logger = CTILogger.get_logger(__name__)
def execute_pipeline():
    logger.info("="*60)
    logger.info(f"🛡️  CTI PLATFORM INTEGRATION TEST - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*60)

    # 1. Mock Data for Testing
    mock_iocs = [
        {
            "type": "cve",
            "value": "CVE-2023-38831",
            "source": "cisa_kev",
            "tags": ["ransomware"]
        },
        {
            "type": "cve",
            "value": "CVE-2021-44228",
            "source": "vulnerability_parser",
            "tags": ["critical"]
        }
    ]

    # 2. Run Deduplication
    print("\n[STEP 1] Deduplication Stage...")
    try:
        # This will now correctly save to storage/final/dd-mm-yy/single.json
        dedup = Deduplicator()
        deduplicated_data = dedup.deduplicate(mock_iocs)
        print(f"✅ Success: {len(deduplicated_data)} items deduplicated.")
    except Exception as e:
        print(f"❌ Deduplication Failed: {e}")
        return

    # 3. Run Enrichment
    print("\n[STEP 2] Enrichment Stage...")
    try:
        # This will pick up the file created in Step 1
        runner = EnrichmentRunner()
        runner.run()
    except Exception as e:
        print(f"❌ Enrichment Failed: {e}")
        return

    print("\n" + "="*60)
    print(f"✨ TEST COMPLETE")
    print(f"📂 Results location: {settings.CURRENT_FINAL_DIR}")
    print("="*60)

if __name__ == "__main__":
    execute_pipeline()