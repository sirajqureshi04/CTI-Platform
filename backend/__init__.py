"""
CTI Platform backend package.
Initializes the namespace and exports the public API safely.
"""
import logging

# Set up package-level logging
logger = logging.getLogger(__name__)

# We use "lazy" module registration. 
# We DO NOT import specific classes here to avoid circular dependencies.
try:
    from . import core
    from . import db
    from . import parser
    from . import feeds
    from . import processors
    from . import Orchestration
    from . import utils

except ImportError as e:
    logger.critical(f"Failed to initialize backend package: {e}")
    raise

# Public API Definition: Shortcuts for high-level modules
__all__ = [
    "core",
    "db",
    "parser",
    "feeds",
    "processors",
    "Orchestration",
    "utils"
]