    """
    CVE tracking module.

    Tracks CVE information, exploitability, and associated IOCs
    from vulnerability feeds.
    """

    import json
    from pathlib import Path
    from typing import Any, Dict, List

    from backend.core.logger import CTILogger

    logger = CTILogger.get_logger(__name__)


    class CVETracker:
        """
        Tracks CVEs and their exploitability status.
        
        Maintains CVE database with KEV status, exploitability,
        and associated threat intelligence.
        """
        
        def __init__(self, data_dir: Path = None):
            """
            Initialize CVE tracker.
            
            Args:
                data_dir: Directory for storing CVE data
            """
            if data_dir is None:
                data_dir = Path(__file__).parent.parent.parent / "data" / "processed"
            self.data_dir = Path(data_dir)
            self.data_dir.mkdir(parents=True, exist_ok=True)
            
            self._cves: Dict[str, Dict[str, Any]] = {}
            self._load_cves()
            
            logger.info(f"Initialized CVE tracker with {len(self._cves)} CVEs")
        
        def _load_cves(self) -> None:
            """Load CVE data from disk and normalize in-memory types."""
            cves_file = self.data_dir / "cves.json"
            if cves_file.exists():
                try:
                    with open(cves_file, "r", encoding="utf-8") as f:
                        loaded = json.load(f)
                    self._cves = {}
                    for cve_id, cve in loaded.items():
                        sources = cve.get("sources") or []
                        if isinstance(sources, list):
                            cve["sources"] = set(sources)
                        elif isinstance(sources, set):
                            cve["sources"] = sources
                        else:
                            cve["sources"] = set()
                        self._cves[cve_id] = cve
                except Exception as e:
                    logger.warning(f"Failed to load CVEs: {e}")
                    self._cves = {}
        
        def _save_cves(self) -> None:
            """Save CVE data to disk (converting sets to lists)."""
            cves_file = self.data_dir / "cves.json"
            try:
                serializable: Dict[str, Dict[str, Any]] = {}
                for cve_id, cve in self._cves.items():
                    data = dict(cve)
                    sources = data.get("sources")
                    if isinstance(sources, set):
                        data["sources"] = list(sources)
                    serializable[cve_id] = data

                with open(cves_file, "w", encoding="utf-8") as f:
                    json.dump(serializable, f, indent=2, default=str)
            except Exception as e:
                logger.error(f"Failed to save CVEs: {e}")
        
        def track_cve(self, cve_id: str, metadata: Dict[str, Any]) -> None:
            """
            Track a CVE with metadata.
            
            Args:
                cve_id: CVE identifier (e.g., CVE-2024-1234)
                metadata: CVE metadata dictionary
            """
            if cve_id not in self._cves:
                self._cves[cve_id] = {
                    "cve_id": cve_id,
                    "first_seen": metadata.get("first_seen"),
                    "last_seen": metadata.get("last_seen"),
                    "sources": set(),
                    "is_kev": False,
                    "exploitability": "unknown"
                }
            
            cve = self._cves[cve_id]
            cve["last_seen"] = metadata.get("last_seen")
            cve["sources"].add(metadata.get("source", "unknown"))
            # Update KEV status
            if metadata.get("source") == "cisa_kev":
                cve["is_kev"] = True
                cve["kev_metadata"] = {
                    "vendor_project": metadata.get("vendor_project"),
                    "product": metadata.get("product"),
                    "vulnerability_name": metadata.get("vulnerability_name"),
                    "required_action": metadata.get("required_action"),
                    "due_date": metadata.get("due_date"),
                    "known_ransomware_campaign_use": metadata.get("known_ransomware_campaign_use")
                }
                cve["exploitability"] = "known_exploited"
            
            self._save_cves()
        
        def get_cve(self, cve_id: str) -> Dict[str, Any]:
            """
            Get CVE information.
            
            Args:
                cve_id: CVE identifier
                
            Returns:
                CVE dictionary or empty dict if not found
            """
            return self._cves.get(cve_id, {})
        
        def get_kev_cves(self) -> List[Dict[str, Any]]:
            """
            Get all CVE KEV entries.
            
            Returns:
                List of KEV CVE dictionaries
            """
            return [cve for cve in self._cves.values() if cve.get("is_kev", False)]
        
        def get_all_cves(self) -> List[Dict[str, Any]]:
            """
            Get all tracked CVEs.
            
            Returns:
                List of CVE dictionaries
            """
            return list(self._cves.values())
        
        def process_iocs(self, iocs: List[Dict[str, Any]]) -> None:
            """
            Process IOCs and extract CVE information.
            
            Args:
                iocs: List of IOC dictionaries
            """
            for ioc in iocs:
                if ioc.get("ioc_type") == "cve":
                    cve_id = ioc.get("ioc_value", "")
                    if cve_id:
                        metadata = ioc.get("metadata", {})
                        metadata["source"] = ioc.get("source")
                        metadata["first_seen"] = ioc.get("first_seen")
                        metadata["last_seen"] = ioc.get("last_seen")
                        self.track_cve(cve_id, metadata)
            
            logger.info(f"Processed CVEs from {len(iocs)} IOCs")

