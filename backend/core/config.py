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
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATA_DIR: Path = BASE_DIR / "data"

    # --------------------------------------------------
    # .env Configuration
    # --------------------------------------------------
    model_config = SettingsConfigDict(
        # Explicitly joining the path as a string to ensure compatibility
        env_file=os.path.join(Path(__file__).resolve().parent.parent.parent, ".env"),
        env_file_encoding='utf-8',
        case_sensitive=True,
        extra='ignore'
    )

    # --------------------------------------------------
    # API Keys (Loaded from .env)
    # --------------------------------------------------
    # Ensure these aliases match the keys in your .env file exactly
    VIRUSTOTAL_API_KEY: Optional[str] = Field(None, alias="VIRUSTOTAL_API_KEY")
    ABUSEIPDB_API_KEY: Optional[str] = Field(None, alias="ABUSEIPDB_API_KEY")
    OTX_API_KEY: Optional[str] = Field(None, alias="OTX_API_KEY")
    MALPEDIA_API_KEY: Optional[str] = Field(None, alias="MALPEDIA_API_KEY")
    OPENAI_API_KEY: Optional[str] = Field(None, alias="OPENAI_API_KEY")
    MAXMIND_LICENSE_KEY: Optional[str] = Field(None, alias="MAXMIND_LICENSE_KEY")

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

    def validate_startup(self):
        """
        Validates critical settings before the pipeline starts.
        """
        # 1. Critical Guardrail for AlienVault OTX
        if self.OTX_INCREMENTAL_ENABLED:
            logger.error("OTX_INCREMENTAL_ENABLED is True. This causes 404s on the OTX API.")
            raise ValueError("Fix OTX_INCREMENTAL_ENABLED in your .env or config.py")

        # 2. Check for missing enrichment keys
        required_keys = {
            "VirusTotal": self.VIRUSTOTAL_API_KEY,
            "AbuseIPDB": self.ABUSEIPDB_API_KEY
        }
        
        for name, key in required_keys.items():
            # Check if key is None, empty string, or whitespace
            if not key or not str(key).strip():
                logger.warning(f"⚠️ {name} API Key is missing. Enrichment via {name} will be disabled.")
            else:
                logger.info(f"✅ {name} API Key loaded successfully.")

@lru_cache()
def get_settings():
    """Returns a singleton instance of settings."""
    try:
        _settings = Settings()
        _settings.validate_startup()
        return _settings
    except Exception as e:
        logger.critical(f"Failed to load configuration: {e}")
        # Log the expected .env path to help debug if it's still missing
        expected_env = os.path.join(Path(__file__).resolve().parent.parent.parent, ".env")
        logger.info(f"Looking for .env at: {expected_env}")
        raise

# Singleton instance
settings = get_settings()