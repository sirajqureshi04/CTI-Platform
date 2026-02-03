"""
Centralized logging module for the CTI platform.
Features structured output, file rotation, and specialized threat-intel levels.
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Optional

class CTILogger:
    """
    Centralized logger with dual-handler support.
    CONSOLE: Human-readable for real-time monitoring.
    FILE: Highly structured for forensic auditing of feed failures.
    """
    
    _loggers: dict[str, logging.Logger] = {}
    # Aligning path with your backend structure
    _log_dir: Path = Path(__file__).resolve().parent.parent.parent / "logs"
    
    @classmethod
    def setup_logging(cls, log_level: str = "INFO", log_file: Optional[str] = None) -> None:
        """
        Configures the root logger. This should be called once at entry point.
        """
        cls._log_dir.mkdir(parents=True, exist_ok=True)
        
        log_path = Path(log_file) if log_file else cls._log_dir / "cti_platform.log"
        
        # Configure root logger
        root_logger = logging.getLogger("cti_platform")
        root_logger.setLevel(getattr(logging, log_level.upper()))
        root_logger.handlers.clear()
        
        # 1. Audit Formatter (Detailed for file storage)
        # Includes: Timestamp, Level, Module Name, Line Number, and the Message.
        audit_formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | [%(name)s] | %(funcName)s:%(lineno)d | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        # 2. Console Formatter (Cleaner for CLI output)
        console_formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S"
        )
        
        # File handler: 10MB limit per file, keeping 5 days of history
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8"
        )
        file_handler.setFormatter(audit_formatter)
        root_logger.addHandler(file_handler)
        
        # Console handler: Direct to stdout
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
        
        root_logger.propagate = False
        root_logger.info(f"Logging initialized. Audit trail: {log_path}")

    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """
        Returns a child logger. Using __name__ ensures we see which scraper 
        or DAO is talking (e.g., cti_platform.backend.scrapers.ransomware)
        """
        if name not in cls._loggers:
            # We prefix with 'cti_platform' so it inherits root settings
            logger_name = f"cti_platform.{name}" if not name.startswith("cti_platform") else name
            cls._loggers[name] = logging.getLogger(logger_name)
        
        return cls._loggers[name]

# Global initialization with default settings
CTILogger.setup_logging()
