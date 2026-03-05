"""
Central configuration settings for the CTI Platform.
All global runtime settings should live here.
"""

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Settings:

    # =============================
    # PROJECT PATHS
    # =============================
    PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
    STORAGE_PATH: Path = PROJECT_ROOT / "storage"
    PROCESSED_PATH: Path = STORAGE_PATH / "processed"
    FINAL_PATH: Path = STORAGE_PATH / "final"

    # =============================
    # DATABASE
    # =============================
    DB_HOST: str = os.getenv("DB_HOST", "localhost")
    DB_PORT: int = int(os.getenv("DB_PORT", "3306"))
    DB_USER: str = os.getenv("DB_USER", "cti_user")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "cti_password")
    DB_NAME: str = os.getenv("DB_NAME", "cti_platform")

    # =============================
    # SCRAPER / PIPELINE
    # =============================
    SCRAPE_INTERVAL_MINUTES: int = int(os.getenv("SCRAPE_INTERVAL_MINUTES", "60"))

    # =============================
    # LOGGING
    # =============================
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # =============================
    # API KEYS
    # =============================
    OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")

    # =============================
    # API ENDPOINTS
    # =============================
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_API_URL: str = "https://api.first.org/data/v1/epss"

    # =============================
    # TOR SETTINGS
    # =============================
    TOR_PROXY: str = os.getenv("TOR_PROXY", "socks5h://127.0.0.1:9050")

    # =============================
    # OUTPUT FILES
    # =============================
    ENRICHED_OUTPUT: Path = FINAL_PATH / "enriched.json"

    def ensure_dirs(self):
        """Ensure required directories exist."""
        self.STORAGE_PATH.mkdir(exist_ok=True)
        self.PROCESSED_PATH.mkdir(exist_ok=True)
        self.FINAL_PATH.mkdir(exist_ok=True)


# Global settings object
settings = Settings()