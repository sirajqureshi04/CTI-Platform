import logging
from typing import Dict, Type, Any
from backend.parser.alienvault_otx_parser import AlienVaultOTXParser
from backend.parser.cisa_kev_parser import CISAKEVParser # Assuming name based on your file tree

logger = logging.getLogger("ParserFactory")

class ParserFactory:
    """Orchestrates which parser class to use for different raw data sources."""
    
    # Registry mapping feed identifiers to their specific Parser Classes
    _parsers: Dict[str, Type] = {
        "alienvault_otx": AlienVaultOTXParser,
        "cisa_kev": CISAKEVParser,
    }

    @classmethod
    def get_parser(cls, feed_name: str, config: Dict[str, Any] = None):
        """Returns an initialized instance of the appropriate parser."""
        parser_class = cls._parsers.get(feed_name.lower())
        
        if not parser_class:
            logger.warning(f"No specific parser found for feed: {feed_name}. Using fallback.")
            return None # Or return a FallbackParser instance if you have one
            
        # Initialize the class with the provided config
        return parser_class(config=config)