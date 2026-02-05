"""Dark Web threat intelligence feeds."""

# Explicit exports for easier importing
from backend.feeds.darkweb.monitor import RansomwareMonitorFeed

__all__ = [
    "RansomwareMonitorFeed"
]       