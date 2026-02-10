import json
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from backend.core.http_client import SecureHTTPClient
from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)

class BaseFeed(ABC):
    def __init__(
        self,
        name: str,
        raw_data_dir: Optional[Path] = None,
        http_client: Optional[SecureHTTPClient] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        self.name = name
        self.config = config or {}
        
        # Capability Flag: Default to True, specific feeds can override this (e.g., OTX)
        self.supports_incremental = True
        
        # 1. Directory Setup
        if raw_data_dir is None:
            raw_data_dir = Path(__file__).parent.parent.parent.parent / "data" / "raw" / self.name.lower().replace(" ", "_")
        self.raw_data_dir = Path(raw_data_dir)
        self.raw_data_dir.mkdir(parents=True, exist_ok=True)
        
        # 2. State Setup (Tracking last fetch)
        self.state_file = self.raw_data_dir / "feed_state.json"
        self.http_client = http_client or SecureHTTPClient()
        
        logger.info(f"Initialized feed: {self.name} (Incremental: {self.supports_incremental})")

    @abstractmethod
    def fetch(self, last_run: Optional[str] = None) -> Dict[str, Any]:
        """Fetch data. If supports_incremental is False, last_run will be ignored."""
        pass

    @abstractmethod
    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate the format of the incoming data."""
        pass

    def get_last_run_time(self) -> Optional[str]:
        """Retrieve last run timestamp only if incremental fetching is supported."""
        if not self.supports_incremental:
            return None
            
        if self.state_file.exists():
            try:
                state = json.loads(self.state_file.read_text())
                return state.get("last_run")
            except Exception:
                return None
        return None

    def save_state(self, timestamp: str):
        """Save the current run timestamp as the new 'last_run'."""
        self.state_file.write_text(json.dumps({"last_run": timestamp}))

    def save_raw_data(self, data: Dict[str, Any]) -> Path:
        """Save raw feed data to disk."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.name}_{timestamp}.json"
        filepath = self.raw_data_dir / filename
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info(f"Saved raw data to {filepath}")
        return filepath

    def dry_run(self) -> Dict[str, Any]:
        """Fetch and validate data without saving, respecting capability flags."""
        last_run = self.get_last_run_time()
        current_run_time = datetime.now().isoformat()
        
        result = {
            "feed_name": self.name,
            "success": False,
            "timestamp": current_run_time,
            "data_summary": {},
            "validation_passed": False,
            "error": None,
            "mode": "incremental" if last_run else "full"
        }
        
        try:
            logger.info(f"[DRY RUN] Fetching ({result['mode']}) data from {self.name}...")
            
            # Capability Check: OTX will ignore last_run inside its fetch logic
            raw_data = self.fetch(last_run=last_run)
            
            data_summary = self._extract_data_summary(raw_data)
            result["data_summary"] = data_summary
            
            validation_passed = self.validate(raw_data)
            result["validation_passed"] = validation_passed
            
            if validation_passed:
                result["success"] = True
                logger.info(f"[DRY RUN] ✓ {self.name}: Fetched {data_summary.get('total_items', 0)} items")
            else:
                result["error"] = "Validation failed"
                
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"[DRY RUN] ✗ {self.name} failed: {e}")
        
        return result

    def _extract_data_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract summary statistics from fetched data."""
        summary = {"total_items": 0, "data_keys": list(data.keys()) if isinstance(data, dict) else []}
        
        if isinstance(data, dict):
            inner_data = data.get("data", {})
            if isinstance(inner_data, dict):
                for key, value in inner_data.items():
                    if isinstance(value, list):
                        summary["total_items"] += len(value)
            elif isinstance(inner_data, list):
                summary["total_items"] = len(inner_data)
        
        return summary

    def run(self) -> Dict[str, Any]:
        """Orchestrates the fetch -> validate -> save flow."""
        last_run = self.get_last_run_time()
        current_run_time = datetime.now().isoformat()
        
        try:
            raw_data = self.fetch(last_run=last_run)
            
            if not self.validate(raw_data):
                raise ValueError(f"Validation failed for {self.name}")
            
            filepath = self.save_raw_data(raw_data)
            self.save_state(current_run_time)
            
            return {"success": True, "file": str(filepath)}
        except Exception as e:
            logger.error(f"Feed {self.name} failed: {e}")
            raise