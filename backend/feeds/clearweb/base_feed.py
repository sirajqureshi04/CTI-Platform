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
        
        # Capability Flag
        self.supports_incremental = True
        
        # 1. Directory Setup
        if raw_data_dir is None:
            raw_data_dir = Path(__file__).parent.parent.parent.parent / "data" / "raw" / self.name.lower().replace(" ", "_")
        self.raw_data_dir = Path(raw_data_dir)
        self.raw_data_dir.mkdir(parents=True, exist_ok=True)
        
        # 2. Resilient Networking Setup
        # We extract network-specific settings from the config, defaulting to CTI-safe values
        # 30s timeout is standard for heavy feeds; 5 retries handles OTX/Malpedia flickering.
        self.timeout = self.config.get("timeout", 30)
        self.max_retries = self.config.get("max_retries", 5)
        
        # 3. State Setup
        self.state_file = self.raw_data_dir / "feed_state.json"
        
        # Initialize SecureHTTPClient with inherited retry/timeout logic
        self.http_client = http_client or SecureHTTPClient(
            timeout=self.timeout,
            max_retries=self.max_retries
        )
        
        logger.info(f"Initialized feed: {self.name} (Retries: {self.max_retries}, Timeout: {self.timeout}s)")

    @abstractmethod
    def fetch(self, last_run: Optional[str] = None) -> Dict[str, Any]:
        pass

    @abstractmethod
    def validate(self, data: Dict[str, Any]) -> bool:
        pass

    def get_last_run_time(self) -> Optional[str]:
        """Retrieve last run timestamp for incremental feeds."""
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
        """Persist last run timestamp."""
        self.state_file.write_text(json.dumps({"last_run": timestamp}))

    def save_raw_data(self, data: Dict[str, Any]) -> Path:
        """Saves JSON evidence to the local filesystem."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.name}_{timestamp}.json"
        filepath = self.raw_data_dir / filename
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        
        return filepath

    def dry_run(self) -> Dict[str, Any]:
        """Diagnostic fetch to test connectivity and data structure."""
        last_run = self.get_last_run_time()
        result = {
            "feed_name": self.name,
            "success": False,
            "validation_passed": False,
            "error": None,
            "mode": "incremental" if last_run else "full"
        }
        
        try:
            raw_data = self.fetch(last_run=last_run)
            result["data_summary"] = self._extract_data_summary(raw_data)
            result["validation_passed"] = self.validate(raw_data)
            result["success"] = result["validation_passed"]
        except Exception as e:
            result["error"] = f"{type(e).__name__}: {str(e)}"
        
        return result

    def _extract_data_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Internal helper for calculating fetch statistics."""
        summary = {"total_items": 0}
        if isinstance(data, dict):
            inner = data.get("data", {})
            if isinstance(inner, dict):
                for v in inner.values():
                    if isinstance(v, list): summary["total_items"] += len(v)
            elif isinstance(inner, list):
                summary["total_items"] = len(inner)
        return summary