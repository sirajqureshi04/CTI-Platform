"""
IOC deduplication processor.

Removes duplicate IOCs using fingerprinting and caching mechanisms.
Supports both in-memory and persistent deduplication tracking.
"""

import json
import pickle
from pathlib import Path
from typing import Dict, List, Set

from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)


class Deduplicator:
    """
    Deduplicates IOCs using fingerprint-based tracking.
    
    Uses SHA256 fingerprints and Bloom filter-like caching for
    efficient duplicate detection across feed runs.
    """
    
    def __init__(self, cache_dir: Path = None, use_bloom: bool = False):
        """
        Initialize deduplicator.
        
        Args:
            cache_dir: Directory for storing deduplication cache
            use_bloom: Whether to use Bloom filter (future enhancement)
        """
        if cache_dir is None:
            if use_bloom:
                cache_dir = Path(__file__).parent.parent / "cache" / "deduplication" / "bloom"
            else:
                cache_dir = Path(__file__).parent.parent / "cache" / "deduplication" / "sha256"
        self.cache_dir = Path(cache_dir)
        
        # Create directory, handling case where path might exist as file
        if self.cache_dir.exists() and not self.cache_dir.is_dir():
            # If it's a file, remove it first
            self.cache_dir.unlink()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.use_bloom = use_bloom
        
        self._seen_fingerprints: Set[str] = set()
        self._load_cache()
        
        cache_size = len(self._seen_fingerprints)
        if cache_size > 0:
            logger.info(f"Initialized deduplicator with {cache_size} cached fingerprints from previous runs")
            logger.debug(f"Cache file: {self.cache_dir / 'fingerprints.pkl'}")
        else:
            logger.info("Initialized deduplicator with empty cache (fresh start)")
    
    def _load_cache(self) -> None:
        """Load deduplication cache from disk."""
        cache_file = self.cache_dir / "fingerprints.pkl"
        if cache_file.exists():
            try:
                with open(cache_file, "rb") as f:
                    self._seen_fingerprints = pickle.load(f)
                logger.debug(f"Loaded {len(self._seen_fingerprints)} fingerprints from cache")
            except Exception as e:
                logger.warning(f"Failed to load deduplication cache: {e}")
                self._seen_fingerprints = set()
    
    def _save_cache(self) -> None:
        """Save deduplication cache to disk."""
        cache_file = self.cache_dir / "fingerprints.pkl"
        try:
            with open(cache_file, "wb") as f:
                pickle.dump(self._seen_fingerprints, f)
            logger.debug(f"Saved {len(self._seen_fingerprints)} fingerprints to cache")
        except Exception as e:
            logger.error(f"Failed to save deduplication cache: {e}")
    
    def deduplicate(self, iocs: List[Dict]) -> List[Dict]:
        """
        Remove duplicate IOCs from list.
        
        Args:
            iocs: List of IOC dictionaries with fingerprint field
            
        Returns:
            List of unique IOCs
        """
        unique_iocs = []
        new_fingerprints = set()
        duplicates = 0
        
        for ioc in iocs:
            fingerprint = ioc.get("fingerprint")
            if not fingerprint:
                logger.warning("IOC missing fingerprint, skipping deduplication")
                unique_iocs.append(ioc)
                continue
            
            if fingerprint in self._seen_fingerprints:
                duplicates += 1
                logger.debug(f"Duplicate IOC detected: {ioc.get('ioc_type')}:{ioc.get('ioc_value')}")
                continue
            
            # New IOC
            unique_iocs.append(ioc)
            new_fingerprints.add(fingerprint)
            self._seen_fingerprints.add(fingerprint)
        
        # Save updated cache
        if new_fingerprints:
            self._save_cache()
        
        logger.info(f"Deduplicated {len(iocs)} IOCs: {len(unique_iocs)} unique, {duplicates} duplicates")
        if duplicates > 0:
            logger.debug(f"Cache contains {len(self._seen_fingerprints)} total fingerprints")
        return unique_iocs
    
    def is_duplicate(self, fingerprint: str) -> bool:
        """
        Check if an IOC fingerprint is already seen.
        
        Args:
            fingerprint: IOC fingerprint
            
        Returns:
            True if duplicate
        """
        return fingerprint in self._seen_fingerprints
    
    def add_fingerprint(self, fingerprint: str) -> None:
        """
        Add a fingerprint to the seen set.
        
        Args:
            fingerprint: IOC fingerprint to add
        """
        if fingerprint not in self._seen_fingerprints:
            self._seen_fingerprints.add(fingerprint)
            self._save_cache()
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get deduplication statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            "total_fingerprints": len(self._seen_fingerprints),
            "cache_file_exists": (self.cache_dir / "fingerprints.pkl").exists()
        }
    
    def clear_cache(self) -> None:
        """Clear deduplication cache."""
        self._seen_fingerprints.clear()
        cache_file = self.cache_dir / "fingerprints.pkl"
        if cache_file.exists():
            cache_file.unlink()
        logger.info("Cleared deduplication cache")

