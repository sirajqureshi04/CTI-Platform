"""Tests for the CTI Platform"""

# Import test modules for easier access
from backend.tests.test_deduplicator import *      # noqa: F401,F403
from backend.tests.test_enrichment import *        # noqa: F401,F403
from backend.tests.test_feeds_dry_run import *     # noqa: F401,F403
from backend.tests.test_parser_storage import *    # noqa: F401,F403
from backend.tests.test_scraper import *           # noqa: F401,F403
from backend.tests.test_storage import *           # noqa: F401,F403

# Define what should be available when importing *
__all__ = [
    # Add specific functions/classes you want to expose
    # For example:
    # 'TestDeduplicator',
    # 'TestEnrichment',
    # 'run_diagnostic',
]

