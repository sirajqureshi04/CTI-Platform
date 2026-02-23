"""
CTI Platform backend package.
This file initializes the backend namespace and exports the public API.
"""

import logging

# Set up package-level logging
logger = logging.getLogger(__name__)

try:
    # --------------------------------------------------
    # 1. Core & Utils
    # --------------------------------------------------
    from .core import TorHTTPClient, SecureHTTPClient, CTILogger
    from .utils import tor_session

    # --------------------------------------------------
    # 2. Database
    # --------------------------------------------------
    from .db import DatabaseConnection, create_tables

    # --------------------------------------------------
    # 3. Feeds (Clearweb & Darkweb)
    # --------------------------------------------------
    from .feeds import (
        RansomwareMonitorFeed, 
        AlienVaultOTXFeed, 
        CISAKEVFeed, 
        MalpediaFeed, 
        RansomwareLiveFeed
    )

    # --------------------------------------------------
    # 4. Processing & Parsing
    # --------------------------------------------------
    from .processors import Deduplicator, IOCNormalizer, RiskEngine
    from .parser import MalwareParser, RansomwareParser, VulnerabilityParser

    # --------------------------------------------------
    # 5. Orchestration (The Brain)
    # --------------------------------------------------
    from .Orchestration import CTIPipeline, Scheduler, FeedManager

except ImportError as e:
    logger.critical(f"Failed to initialize backend package: {e}")
    # We raise the error to prevent the app from running in a broken state
    raise

# --------------------------------------------------
# Public API Definition
# --------------------------------------------------
__all__ = [
    # Core
    "TorHTTPClient",
    "SecureHTTPClient",
    "CTILogger",
    "tor_session",
    
    # Database
    "DatabaseConnection",
    "create_tables",
    
    # Feeds
    "RansomwareMonitorFeed",
    "AlienVaultOTXFeed",
    "CISAKEVFeed",
    "MalpediaFeed",
    "RansomwareLiveFeed",
    
    # Orchestration
    "CTIPipeline",
    "Scheduler",
    "FeedManager",
    
    # Processors
    "Deduplicator",
    "IOCNormalizer",
    "RiskEngine",
]