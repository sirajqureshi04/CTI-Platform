import os
import shutil
import logging
from backend.db.daos.indicator_dao import IndicatorDAO
# Import your actual parsers here
from backend.parsers.otx_parser import parse_otx_file 

RAW_BASE = "storage/raw/"
ARCHIVE_BASE = "storage/archive/"

def run_processor():
    dao = IndicatorDAO()
    
    # Iterate through each feed's folder (e.g., alienvault_otx)
    for feed_name in os.listdir(RAW_BASE):
        feed_path = os.path.join(RAW_BASE, feed_name)
        if not os.path.isdir(feed_path): continue

        for filename in os.listdir(feed_path):
            if filename.endswith(".json"):
                raw_file = os.path.join(feed_path, filename)
                
                try:
                    # 1. Dispatch to the right parser
                    if "otx" in feed_name:
                        indicators = parse_otx_file(raw_file)
                    
                    # 2. Save to MySQL
                    for ind in indicators:
                        dao.upsert_indicator(ind)

                    # 3. Archive the raw file
                    archive_path = os.path.join(ARCHIVE_BASE, feed_name)
                    os.makedirs(archive_path, exist_ok=True)
                    shutil.move(raw_file, os.path.join(archive_path, filename))
                    
                    logging.info(f"Successfully processed and archived {filename}")
                except Exception as e:
                    logging.error(f"Failed to process {filename}: {e}")