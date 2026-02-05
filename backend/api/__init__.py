"""API module for the CTI platform."""

# Explicit exports for easier importing
from backend.api.app import create_app
from backend.api.auth import APIAuth
from backend.api.routes import feeds, incidents, stats

__all__ = [
    "create_app",
    "APIAuth",
    "feeds",
    "incidents",
    "stats"
]       
