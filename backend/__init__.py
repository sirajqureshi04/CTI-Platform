"""CTI Platform backend package."""

# Explicit exports for easier importing
from backend.core import TorHTTPClient, SecureHTTPClient, CTILogger
from backend.db import DatabaseConnection, create_tables
from backend.feeds import RansomwareMonitorFeed, AlienVaultOTXFeed, CISAKEVFeed, MalpediaFeed, RansomwareLiveFeed
from backend.Orchestration import CTIPipeline, Scheduler, FeedManager
from backend.processors import Deduplicator, IOCNormalizer, RiskEngine
from backend.parser import MalwareParser, RansomwareParser, VulnerabilityParser
from backend.scripts import test_connection
from backend.utils import tor_session

__all__ = [
    "TorHTTPClient",