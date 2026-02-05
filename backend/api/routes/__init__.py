"""API route modules for the CTI platform."""

# Explicit exports for easier importing
from backend.api.routes.feeds import bp as feeds_bp
from backend.api.routes.incidents import bp as incidents_bp
from backend.api.routes.stats import bp as stats_bp

__all__ = [
    "feeds_bp",
    "incidents_bp",
    "stats_bp"
]           
