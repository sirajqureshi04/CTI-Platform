import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Setup basic logging for startup checks
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Config")

class Settings(BaseSettings):
    # --------------------------------------------------
    # Application & Paths
    # --------------------------------------------------
    APP_NAME: str = "CTI Platform"
    ENV: str = "development"
    
    # Root calculation: Points to the CTI-Platform root directory
    # If config.py is in backend/core/config.py, we need to go up 3 levels
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    
    # Storage paths (Ensuring these align with manager.py)
    STORAGE_DIR: Path = BASE_DIR / "storage"
    FINAL_INTEL_FILE: Path = STORAGE_DIR / "final" / "final_intelligence.json"
    
    # MaxMind Path
    MAXMIND_DB_PATH: Path = BASE_DIR / "data" / "GeoLite2-City.mmdb"

    # --------------------------------------------------
    # .env Configuration
    # --------------------------------------------------
    model_config = SettingsConfigDict(
        # Use an absolute path for the .env file to avoid issues during -m execution
        env_file=str(Path(__file__).resolve().parent.parent.parent / ".env"),
        env_file_encoding='utf-8',
        case_sensitive=True,
        extra='ignore'
    )

    # --------------------------------------------------
    # API Keys (Loaded from .env)
    # --------------------------------------------------
    VIRUSTOTAL_API_KEY: Optional[str] = Field(None)
    ABUSEIPDB_API_KEY: Optional[str] = Field(None)
    OTX_API_KEY: Optional[str] = Field(None)
    MALPEDIA_API_KEY: Optional[str] = Field(None)
    OPENAI_API_KEY: Optional[str] = Field(None)
    MAXMIND_LICENSE_KEY: Optional[str] = Field(None)

    # --------------------------------------------------
    # Database Settings
    # --------------------------------------------------
    DB_HOST: str = "localhost"
    DB_USER: str = "cti_user"
    DB_PASSWORD: str = "secure_password"
    DB_NAME: str = "cti_database"
    DB_PORT: int = 3306

    # --------------------------------------------------
    # Feed & Enrichment Constraints
    # --------------------------------------------------
    OTX_INCREMENTAL_ENABLED: bool = False
    OTX_MAX_PAGES: int = 5 
    VT_RATE_LIMIT_DELAY: int = 15  # Seconds between VT requests
    
    # NEW: Clearweb Feed Toggle for Dry Runs
    DRY_RUN_MOCK_FEEDS: bool = True

    def validate_startup(self):
        """
        Validates critical settings before the pipeline starts.
        """
        # 1. Guardrail for OTX
        if self.OTX_INCREMENTAL_ENABLED:
            logger.error("OTX_INCREMENTAL_ENABLED is True. This causes 404s on the OTX API.")
            raise ValueError("Fix OTX_INCREMENTAL_ENABLED in your .env or config.py")

        # 2. Check for missing enrichment keys
        required_keys = {
            "VirusTotal": self.VIRUSTOTAL_API_KEY,
            "AbuseIPDB": self.ABUSEIPDB_API_KEY
        }
        
        for name, key in required_keys.items():
            # More robust check for "None" string or empty values
            if not key or str(key).lower() in ["none", "", "your_key_here"]:
                logger.warning(f"⚠️ {name} API Key is missing. Enrichment via {name} will be disabled.")
            else:
                # Obfuscate key in logs for security
                masked_key = f"{key[:4]}...{key[-4:]}" if len(str(key)) > 8 else "****"
                logger.info(f"✅ {name} API Key loaded successfully: {masked_key}")

        # 3. Check for MaxMind DB
        if not self.MAXMIND_DB_PATH.exists():
            logger.warning(f"⚠️ MaxMind DB not found at {self.MAXMIND_DB_PATH}. GeoIP lookups will use fallback.")

@lru_cache()
def get_settings():
    """Returns a singleton instance of settings."""
    try:
        _settings = Settings()
        _settings.validate_startup()
        return _settings
    except Exception as e:
        logger.critical(f"Failed to load configuration: {e}")
        raise

# Singleton instance
settings = get_settings()