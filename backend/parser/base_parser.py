import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Recommendation: Use 'orjson' for 3x-10x faster JSON serialization if installed
try:
    import orjson as json_lib
except ImportError:
    import json as json_lib

from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)

class BaseParser(ABC):
    def __init__(
        self,
        name: str,
        processed_data_dir: Optional[Path] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        self.name = name
        self.config = config or {}
        
        # Setup path: Using resolve() to handle relative pathing safely
        if processed_data_dir is None:
            processed_data_dir = Path(__file__).resolve().parents[3] / "data" / "processed"
        
        self.processed_data_dir = Path(processed_data_dir)
        self.processed_data_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initialized parser: {self.name}")

    @abstractmethod
    def parse(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Implementation remains the same: Child class logic here."""
        pass

    @abstractmethod
    def extract_iocs(self, parsed_data: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
        """Efficiency Change: Returning a Set instead of List to auto-deduplicate."""
        pass

    def normalize_ioc(
        self,
        ioc_type: str,
        ioc_value: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Normalization Change: Standardizing time to UTC and cleaning inputs."""
        now_utc = datetime.now(timezone.utc).isoformat()
        
        return {
            "ioc_type": ioc_type.lower().strip(),
            "ioc_value": str(ioc_value).strip().lower() if ioc_type != 'cve' else ioc_value.strip().upper(),
            "source": self.name,
            "parsed_at": now_utc,
            "first_seen": metadata.get("first_seen", now_utc) if metadata else now_utc,
            "metadata": metadata or {}
        }

    def save_processed_data(self, data: List[Dict[str, Any]]) -> Path:
        """Efficiency Change: Using context managers and fast serialization."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.name}_{timestamp}.json"
        filepath = self.processed_data_dir / filename
        
        try:
            # Using 'wb' for binary if using orjson, 'w' for standard json
            mode = 'wb' if 'orjson' in str(json_lib) else 'w'
            with open(filepath, mode, encoding=None if mode == 'wb' else "utf-8") as f:
                if mode == 'wb':
                    f.write(json_lib.dumps(data, option=json_lib.OPT_INDENT_2))
                else:
                    json_lib.dump(data, f, indent=2, default=str)
            
            return filepath
        except Exception as e:
            logger.error(f"Failed to save {self.name}: {e}")
            raise

    def run(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execution remains clean, but with better summary metrics."""
        start_time = datetime.now()
        try:
            parsed_data = self.parse(raw_data)
            iocs = self.extract_iocs(parsed_data)
            filepath = self.save_processed_data(parsed_data)
            
            duration = (datetime.now() - start_time).total_seconds()
            
            return {
                "success": True,
                "parser": self.name,
                "runtime_sec": round(duration, 3),
                "processed_file": str(filepath),
                "total_items": len(parsed_data),
                "unique_iocs": sum(len(v) for v in iocs.values()),
                "breakdown": {k: len(v) for k, v in iocs.items()}
            }
        except Exception as e:
            logger.error(f"Execution failed for {self.name}: {e}")
            return {"success": False, "error": str(e)}
