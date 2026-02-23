import os
import json
import glob
import time
from datetime import datetime

# REFINED IMPORTS: Using absolute package paths for reliability
from backend.enrichment.geoip_lookup import GeoIPEnricher
from backend.enrichment.whois_lookup import WhoisEnricher

class EnrichmentManager:
    def __init__(self):
        # Paths relative to the project root (CTI-Platform)
        self.storage_path = "storage/final/"
        self.cache_path = "backend/cache/enrichment_state.json"
        
        # Initialize sub-modules
        self.geoip = GeoIPEnricher()
        self.whois = WhoisEnricher()
        
    def get_latest_report(self):
        """Finds the most recent daily intel report."""
        if not os.path.exists(self.storage_path):
            os.makedirs(self.storage_path, exist_ok=True)
            return None
            
        files = glob.glob(os.path.join(self.storage_path, "intel_report_*.json"))
        if not files:
            return None
        return max(files, key=os.path.getctime)

    def process_report(self):
        report_path = self.get_latest_report()
        if not report_path:
            print("[-] No reports found in storage/final/ to enrich.")
            return

        print(f"[*] Starting enrichment for: {report_path}")
        
        try:
            with open(report_path, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"[!] Error loading report: {e}")
            return

        enriched_count = 0
        
        # Iterate through the unified indicators
        for indicator in data.get("indicators", []):
            # Skip if already enriched to save API credits/time
            if indicator.get("enrichment"):
                continue

            ind_type = indicator.get("type", "").lower()
            ind_value = indicator.get("value")

            # Routing Logic
            if ind_type == "ipv4":
                indicator["enrichment"] = self.enrich_ip(ind_value)
                enriched_count += 1
            
            elif ind_type in ["domain", "url"]:
                indicator["enrichment"] = self.enrich_domain(ind_value)
                enriched_count += 1

            # Future expansion: elif ind_type == "cve": ...

        # Save back to the SAME file (In-place update)
        with open(report_path, 'w') as f:
            json.dump(data, f, indent=4)
        
        print(f"[+] Enrichment Complete. Updated {enriched_count} new indicators.")

    def enrich_ip(self, ip):
        """Coordinates multiple IP lookups"""
        res = {}
        try:
            # Calls the GeoIPEnricher class
            res["geo"] = self.geoip.get_data(ip)
        except Exception as e:
            res["error"] = f"GeoIP Error: {str(e)}"
        return res

    def enrich_domain(self, domain):
        """Coordinates domain lookups"""
        res = {}
        try:
            # Calls the WhoisEnricher class
            res["whois"] = self.whois.get_data(domain)
        except Exception as e:
            res["error"] = f"Whois Error: {str(e)}"
        return res

if __name__ == "__main__":
    # This allows running the manager standalone for manual testing
    manager = EnrichmentManager()
    manager.process_report()