"""
IOC extractor for pulling IOCs from various data formats.

Extracts IOCs from parsed feed data and organizes them by type
for further processing and storage.
"""

from typing import Any, Dict, List

from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)


class IOCExtractor:
    """
    Extracts and organizes IOCs from parsed data.
    
    Groups IOCs by type and provides statistics and filtering
    capabilities.
    """
    
    def __init__(self):
        """Initialize IOC extractor."""
        logger.info("Initialized IOC extractor")
    
    def extract(self, parsed_data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract IOCs organized by type.
        
        Args:
            parsed_data: List of parsed IOC dictionaries
            
        Returns:
            Dictionary mapping IOC types to lists of IOCs
        """
        iocs_by_type: Dict[str, List[Dict[str, Any]]] = {}
        
        for ioc in parsed_data:
            ioc_type = ioc.get("ioc_type", "unknown")
            
            if ioc_type not in iocs_by_type:
                iocs_by_type[ioc_type] = []
            
            iocs_by_type[ioc_type].append(ioc)
        
        logger.info(f"Extracted IOCs: {sum(len(v) for v in iocs_by_type.values())} total across {len(iocs_by_type)} types")
        return iocs_by_type
    
    def get_statistics(self, iocs_by_type: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Get statistics for extracted IOCs.
        
        Args:
            iocs_by_type: Dictionary of IOCs organized by type
            
        Returns:
            Dictionary with statistics
        """
        stats = {
            "total_iocs": sum(len(v) for v in iocs_by_type.values()),
            "by_type": {k: len(v) for k, v in iocs_by_type.items()},
            "types": list(iocs_by_type.keys())
        }
        
        return stats
    
    def filter_by_type(self, iocs_by_type: Dict[str, List[Dict[str, Any]]], types: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Filter IOCs by type.
        
        Args:
            iocs_by_type: Dictionary of IOCs organized by type
            types: List of IOC types to include
            
        Returns:
            Filtered dictionary
        """
        filtered = {k: v for k, v in iocs_by_type.items() if k in types}
        logger.info(f"Filtered to {len(filtered)} IOC types")
        return filtered

