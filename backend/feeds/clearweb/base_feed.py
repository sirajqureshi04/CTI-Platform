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
        self.supports_incremental = True

        if raw_data_dir is None:
            root = Path(__file__).parent.parent.parent.parent
            self.raw_data_dir = root / "storage" / "raw" / self.name.lower().replace(" ", "_")
        else:
            self.raw_data_dir = Path(raw_data_dir)

        self.raw_data_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.raw_data_dir / "feed_state.json"
        self.http_client = http_client or SecureHTTPClient()

    @abstractmethod
    def fetch(self, last_run: Optional[str] = None) -> Dict[str, Any]:
        pass

    @abstractmethod
    def validate(self, data: Dict[str, Any]) -> bool:
        pass

    def save_raw_data(self, data: Dict[str, Any]) -> Path:
        timestamp = datetime.utcnow().strftime("%Y-%m-%d")
        filename = f"{timestamp}_raw.json"
        filepath = self.raw_data_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        logger.info(f"Saved raw data to {filepath}")
        return filepath

    def dry_run(self) -> Dict[str, Any]:
        last_run = self.get_last_run_time()
        raw_data = self.fetch(last_run=last_run)

        pulses = raw_data.get("data", {}).get("pulses", [])
        validation_passed = self.validate(raw_data)

        if validation_passed:
            saved_path = self.save_raw_data(raw_data)
            return {
                "feed_name": self.name,
                "success": True,
                "validation_passed": True,
                "data_summary": {
                    "total_items": len(pulses)
                },
                "saved_at": str(saved_path)
            }

        return {
            "feed_name": self.name,
            "success": False,
            "validation_passed": False,
            "data_summary": {
                "total_items": len(pulses)
            },
            "error": "Validation failed"
        }

    def get_last_run_time(self) -> Optional[str]:
        if self.state_file.exists():
            try:
                return json.loads(self.state_file.read_text()).get("last_run")
            except Exception:
                return None
        return None