import os

class VictimProvider:
    def __init__(self):
        self.vendor_path = os.path.join(os.path.dirname(__file__), "..", "data", "my_vendors.txt")

    def _get_vendors(self):
        if not os.path.exists(self.vendor_path): return []
        with open(self.vendor_path, "r") as f:
            return [line.strip().lower() for line in f]

    def enrich(self, ioc: dict) -> dict:
        victim = ioc["value"].lower()
        vendors = self._get_vendors()
        
        is_vendor = any(v in victim for v in vendors)
        
        ioc["enrichment"] = {
            "supply_chain_risk": is_vendor,
            "category": "Peer/Target" if not is_vendor else "Direct Vendor"
        }
        
        if is_vendor:
            ioc["severity"] = "critical"
            
        return ioc