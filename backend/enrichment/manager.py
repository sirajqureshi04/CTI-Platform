import os
import json
import glob
import time
from datetime import datetime

# Import your existing lookups
# Assuming your folder structure: enrichment/manager.py
from geoip_lookup import GeoIPEnricher
from whois_lookup import WhoisEnricher
# from providers.epss_cve import EPSSProvider  # Future addition

class EnrichmentManager:
    def __init__(self):
        self.storage_path = "storage/final/"
        self.cache_path = "backend/cache/enrichment_state.json"
        
        # Initialize sub-modules
        self.geoip = GeoIPEnricher()
        self.whois = WhoisEnricher()
        
    def get_latest_report(self):
        """Finds the most recent daily intel report."""
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
        
        with open(report_path, 'r') as f:
            data = json.load(f)

        enriched_count = 0
        
        # Iterate through the unified indicators
        for indicator in data.get("indicators", []):
            # Skip if already enriched to save API credits
            if "enrichment" in indicator and indicator["enrichment"]:
                continue

            ind_type = indicator.get("type")
            ind_value = indicator.get("value")

            # Routing Logic
            if ind_type == "ipv4":
                indicator["enrichment"] = self.enrich_ip(ind_value)
                enriched_count += 1
            
            elif ind_type in ["domain", "url"]:
                indicator["enrichment"] = self.enrich_domain(ind_value)
                enriched_count += 1

            elif ind_type == "cve":
                # indicator["enrichment"] = self.enrich_cve(ind_value)
                pass

            # Respect Free Tier limits (Safety Brake)
            # time.sleep(1) 

        # Save back to the SAME file (In-place update)
        with open(report_path, 'w') as f:
            json.dump(data, f, indent=4)
        
        print(f"[+] Enrichment Complete. Updated {enriched_count} new indicators.")

    def enrich_ip(self, ip):
        """Coordinates multiple IP lookups"""
        res = {}
        try:
            res["geo"] = self.geoip.get_data(ip)
            # Add reputation_check logic here later
        except Exception as e:
            res["error"] = str(e)
        return res

    def enrich_domain(self, domain):
        """Coordinates domain lookups"""
        res = {}
        try:
            res["whois"] = self.whois.get_data(domain)
        except Exception as e:
            res["error"] = str(e)
        return res

if __name__ == "__main__":
    manager = EnrichmentManager()
    manager.process_report()