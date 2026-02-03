"""
IOC normalizer for standardizing IOC formats and values.

Normalizes IOCs to ensure consistent format, validation, and
canonical representation across all sources.
"""

import hashlib
import ipaddress
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)


class IOCNormalizer:
    """
    Normalizes IOCs to standard formats.
    
    Provides validation and canonical representation for:
    - IP addresses (IPv4/IPv6)
    - Domains
    - URLs
    - File hashes (MD5, SHA1, SHA256)
    - CVEs
    - Email addresses
    """
    
    # Validation patterns
    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    EMAIL_PATTERN = re.compile(
        r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$'
    )
    MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
    SHA1_PATTERN = re.compile(r'^[a-fA-F0-9]{40}$')
    SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
    CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)
    
    def __init__(self):
        """Initialize IOC normalizer."""
        logger.info("Initialized IOC normalizer")
    
    def normalize(self, ioc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize a single IOC.
        
        Args:
            ioc: IOC dictionary with ioc_type and ioc_value
            
        Returns:
            Normalized IOC dictionary or None if invalid
        """
        ioc_type = ioc.get("ioc_type", "").lower()
        ioc_value = str(ioc.get("ioc_value", "")).strip()
        
        if not ioc_value:
            return None
        
        normalized_value = None
        
        try:
            if ioc_type == "ip":
                normalized_value = self._normalize_ip(ioc_value)
            elif ioc_type == "domain":
                normalized_value = self._normalize_domain(ioc_value)
            elif ioc_type == "url":
                normalized_value = self._normalize_url(ioc_value)
            elif ioc_type in ["hash", "md5", "sha1", "sha256"]:
                normalized_value = self._normalize_hash(ioc_value, ioc_type)
            elif ioc_type == "cve":
                normalized_value = self._normalize_cve(ioc_value)
            elif ioc_type == "email":
                normalized_value = self._normalize_email(ioc_value)
            else:
                logger.warning(f"Unknown IOC type: {ioc_type}")
                normalized_value = ioc_value.lower()
        except Exception as e:
            logger.warning(f"Failed to normalize IOC {ioc_type}:{ioc_value}: {e}")
            return None
        
        if normalized_value is None:
            return None
        
        # Create normalized IOC
        normalized = ioc.copy()
        normalized["ioc_type"] = ioc_type
        normalized["ioc_value"] = normalized_value
        normalized["normalized"] = True
        
        # Generate fingerprint for deduplication
        normalized["fingerprint"] = self._generate_fingerprint(ioc_type, normalized_value)
        
        return normalized
    
    def normalize_batch(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Normalize a batch of IOCs.
        
        Args:
            iocs: List of IOC dictionaries
            
        Returns:
            List of normalized IOC dictionaries
        """
        normalized = []
        for ioc in iocs:
            norm_ioc = self.normalize(ioc)
            if norm_ioc:
                normalized.append(norm_ioc)
        
        logger.info(f"Normalized {len(normalized)}/{len(iocs)} IOCs")
        return normalized
    
    def _normalize_ip(self, ip: str) -> Optional[str]:
        """Normalize IP address."""
        try:
            # Remove port if present
            if ":" in ip and not ip.startswith("["):  # IPv6 check
                ip = ip.split(":")[0]
            
            ip_obj = ipaddress.ip_address(ip)
            return str(ip_obj)
        except ValueError:
            logger.debug(f"Invalid IP address: {ip}")
            return None
    
    def _normalize_domain(self, domain: str) -> Optional[str]:
        """Normalize domain name."""
        # Remove protocol if present
        domain = domain.replace("http://", "").replace("https://", "")
        # Remove path
        domain = domain.split("/")[0]
        # Remove port
        domain = domain.split(":")[0]
        # Remove trailing dot
        domain = domain.rstrip(".")
        # Convert to lowercase
        domain = domain.lower()
        
        # Validate
        if self.DOMAIN_PATTERN.match(domain):
            return domain
        
        logger.debug(f"Invalid domain: {domain}")
        return None
    
    def _normalize_url(self, url: str) -> Optional[str]:
        """Normalize URL."""
        try:
            # Add protocol if missing
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            
            parsed = urlparse(url)
            
            # Validate domain
            if not parsed.netloc:
                return None
            
            # Reconstruct normalized URL
            normalized = f"{parsed.scheme}://{parsed.netloc.lower()}"
            if parsed.path:
                normalized += parsed.path
            if parsed.query:
                normalized += "?" + parsed.query
            
            return normalized
        except Exception as e:
            logger.debug(f"Invalid URL: {url}: {e}")
            return None
    
    def _normalize_hash(self, hash_value: str, hash_type: str) -> Optional[str]:
        """Normalize file hash."""
        hash_value = hash_value.lower().strip()
        
        # Determine hash type if not specified
        if hash_type == "hash":
            if self.MD5_PATTERN.match(hash_value):
                hash_type = "md5"
            elif self.SHA1_PATTERN.match(hash_value):
                hash_type = "sha1"
            elif self.SHA256_PATTERN.match(hash_value):
                hash_type = "sha256"
            else:
                return None
        
        # Validate based on type
        if hash_type == "md5" and self.MD5_PATTERN.match(hash_value):
            return hash_value
        elif hash_type == "sha1" and self.SHA1_PATTERN.match(hash_value):
            return hash_value
        elif hash_type == "sha256" and self.SHA256_PATTERN.match(hash_value):
            return hash_value
        
        logger.debug(f"Invalid hash: {hash_value} (type: {hash_type})")
        return None
    
    def _normalize_cve(self, cve: str) -> Optional[str]:
        """Normalize CVE identifier."""
        cve = cve.upper().strip()
        if self.CVE_PATTERN.match(cve):
            return cve
        return None
    
    def _normalize_email(self, email: str) -> Optional[str]:
        """Normalize email address."""
        email = email.lower().strip()
        if self.EMAIL_PATTERN.match(email):
            return email
        return None
    
    def _generate_fingerprint(self, ioc_type: str, ioc_value: str) -> str:
        """
        Generate fingerprint for IOC deduplication.
        
        Args:
            ioc_type: IOC type
            ioc_value: Normalized IOC value
            
        Returns:
            SHA256 fingerprint
        """
        data = f"{ioc_type}:{ioc_value}".encode("utf-8")
        return hashlib.sha256(data).hexdigest()

