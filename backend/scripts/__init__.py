"""Scripts for the CTI platform."""

# Explicit exports for easier importing
from backend.scripts.test_tor import test_connection
from backend.scripts.test_scraper import run_diagnostic          # noqa: F401
from backend.scripts.test_tor import test_connection          # noqa: F401

__all__ = [
    "run_diagnostic",
    "test_connection",
]       