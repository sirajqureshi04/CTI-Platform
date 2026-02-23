"""
Parser modules for processing raw feed data.
"""

# Keep this empty or use absolute imports without referencing the parent 'backend' package if possible.
# By removing the eager imports here, we stop the circular crash.

__all__ = [
    "MalpediaParser",
    "RansomwareParser",
    "AlienVaultOTXParser",
    "CISAKEVParser",
]