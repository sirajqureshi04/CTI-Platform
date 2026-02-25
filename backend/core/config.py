import os
from pathlib import Path
from dotenv import load_dotenv

# Load variables from .env (API Keys, etc.)
load_dotenv()

class Config:
    """
    Centralized configuration for the CTI Platform.
    Handles Secrets, Network Settings, and Enrichment Paths.
    """
    
    # --- 1. PROJECT PATHS (Absolute) ---
    BACKEND_DIR = Path(__file__).parent.absolute()
    PROJECT_ROOT = BACKEND_DIR.parent
    
    # Enrichment Data
    VENDOR_LIST_PATH = BACKEND_DIR / "enrichment" / "data" / "my_vendors.txt"
    
    # Storage Paths
    RAW_STORAGE = PROJECT_ROOT / "storage" / "raw"
    FINAL_STORAGE = PROJECT_ROOT / "storage" / "final"
    ENRICHED_OUTPUT = FINAL_STORAGE / "enriched_intelligence.json"
    
    # --- 2. SECRETS & API TOKENS (From .env) ---
    NVD_API_KEY = os.getenv("NVD_API_KEY", "")
    MALPEDIA_TOKEN = os.getenv("MALPEDIA_TOKEN", "")
    
    # --- 3. NETWORK & TOR SETTINGS ---
    # Fixed to 9050 to match your successful netstat diagnostic
    TOR_SOCKS_PROXY = "socks5h://127.0.0.1:9050"
    REQUEST_TIMEOUT = 20
    USER_AGENT = "CTI-Intelligence-Enricher/1.0"

    # --- 4. ENRICHMENT SOURCE URLS ---
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_API_URL = "https://api.first.org/data/v1/epss"
    RANSOMWARE_LIVE_API = "https://api.ransomware.live/v2/recentvictims"
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # --- 5. ENRICHMENT LOGIC SETTINGS ---
    EPSS_THRESHOLD = 0.45  # Scores above this are flagged as high risk
    CONFIDENCE_LEVEL_MIN = 50
    DEBUG_MODE = True

    @staticmethod
    def ensure_dirs():
        """Creates necessary directories if they don't exist."""
        dirs = [
            Config.FINAL_STORAGE, 
            Config.RAW_STORAGE, 
            Config.BACKEND_DIR / "enrichment" / "data"
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

# Run directory check on import
Config.ensure_dirs()