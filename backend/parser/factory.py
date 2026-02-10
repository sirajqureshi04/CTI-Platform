from typing import Callable, Dict
import logging
# Import your specific parser functions here
# from backend.parsers.otx_parser import parse_otx_raw
# from backend.parsers.cisa_parser import parse_cisa_raw

class ParserFactory:
    """Orchestrates which parser to use for different raw data sources."""
    
    # Registry mapping feed identifiers to their specific parsing functions
    _parsers: Dict[str, Callable] = {
        # "alienvault_otx": parse_otx_raw,
        # "cisa_alerts": parse_cisa_raw,
    }

    @classmethod
    def get_parser(cls, feed_name: str) -> Callable:
        """Returns the appropriate parser function for a given feed name."""
        parser = cls._parsers.get(feed_name.lower())
        if not parser:
            logging.warning(f"No specific parser found for feed: {feed_name}. Using fallback.")
            return cls._fallback_parser
        return parser

    @staticmethod
    def _fallback_parser(file_path: str):
        """A safety parser that handles unknown formats gracefully."""
        logging.error(f"Cannot parse unknown source at {file_path}")
        return []