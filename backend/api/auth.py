"""
Authentication module for API.

Provides API key and token-based authentication for
securing the CTI platform API endpoints.
"""

import hashlib
import os
from functools import wraps
from typing import Optional

from flask import request

from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)


class APIAuth:
    """
    API authentication handler.
    
    Supports API key and token-based authentication.
    """
    
    def __init__(self):
        """Initialize API auth."""
        # Load API key from environment or use default
        self.api_key = os.getenv("CTI_API_KEY", "default_api_key_change_in_production")
        logger.info("Initialized API authentication")
    
    def verify_api_key(self, api_key: Optional[str]) -> bool:
        """
        Verify API key.
        
        Args:
            api_key: API key to verify
            
        Returns:
            True if valid
        """
        if not api_key:
            return False
        
        # Simple comparison (in production, use secure comparison)
        return api_key == self.api_key
    
    def require_auth(self, f):
        """
        Decorator to require API authentication.
        
        Args:
            f: Function to protect
            
        Returns:
            Decorated function
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
            
            if not self.verify_api_key(api_key):
                return {"error": "Unauthorized"}, 401
            
            return f(*args, **kwargs)
        
        return decorated_function


# Global auth instance
auth = APIAuth()

