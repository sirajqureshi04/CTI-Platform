"""
Centralized application configuration with startup guardrails.
Enforces OTX non-incremental constraints and automated .env loading.
"""

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --------------------------------------------------
    # Application & Paths
    # --------------------------------------------------
    APP_NAME: str = "CTI Platform"
    ENV: str = "development"
    
    # Automatically locate the project root
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATA_DIR: Path = BASE_DIR / "data"

    # --------------------------------------------------
    # .env File Configuration (NEW & OPTIMIZED)
    # --------------------------------------------------
    # This tells Pydantic exactly where to find your .env file
    # relative to this file's location.
    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parent.parent.parent / ".env",
        env_file_encoding='utf-8',
        case_sensitive=True,
        extra='ignore'
    )

    # --------------------------------------------------
    # MySQL Database (Automatically filled from .env)
    # --------------------------------------------------
    DB_HOST: str = "localhost"
    DB_USER: str = "cti_user"
    DB_PASSWORD: str = "secure_password"
    DB_NAME: str = "cti_database"
    DB_PORT: int = 3306
    DB_POOL_SIZE: int = 10

    # --------------------------------------------------
    # Feed Constraints (GUARDRAIL FIX)
    # --------------------------------------------------
    # Enforced as False to prevent 404 errors on AlienVault OTX
    OTX_INCREMENTAL_ENABLED: bool = False
    OTX_MAX_PAGES: int = 5 

    # --------------------------------------------------
    # API Keys (Automatically filled from .env)
    # --------------------------------------------------
    OTX_API_KEY: Optional[str] = None
    MALPEDIA_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    MAXMIND_LICENSE_KEY: Optional[str] = None

    # --------------------------------------------------
    # Orchestrator Settings
    # --------------------------------------------------
    SCRAPE_INTERVAL_MINUTES: int = 60
    MAX_PARALLEL_SCRAPERS: int = 5

    def validate_startup(self):
        """
        Critical startup checks to prevent pipeline failures.
        """
        if not self.OTX_API_KEY:
            print("⚠️ WARNING: OTX_API_KEY is missing. OTX feed will default to Public pulses.")
        
        # Hard guardrail against the 404 error logic
        if self.OTX_INCREMENTAL_ENABLED:
            raise ValueError(
                "CRITICAL CONFIG ERROR: OTX_INCREMENTAL_ENABLED is True. "
                "The AlienVault API will return 404. Change this to False in your .env file."
            )

@lru_cache()
def get_settings():
    """Returns a cached instance of settings to avoid reloading .env constantly."""
    settings = Settings()
    settings.validate_startup()
    return settings

# Create a singleton instance for easy import
settings = get_settings()