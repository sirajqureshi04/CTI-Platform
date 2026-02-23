import os
import json
import time
from datetime import datetime

# REFINED IMPORTS: Using absolute package paths for reliability
from backend.enrichment.geoip_lookup import GeoIPEnricher
from backend.enrichment.whois_lookup import WhoisEnricher

class EnrichmentManager:
    def __init__(self):
        # UPDATED: Direct path to your target file as specified
        self.storage_path = "storage/final"
        self.target_file = os.path.join(self.storage_path, "final_intelligence.json")
        self.cache_path = "backend/cache/enrichment_state.json"
        
        # Initialize sub-modules
        self.geoip = GeoIPEnricher()
        self.whois = WhoisEnricher()
        
    def get_report(self):
        """Validates and returns the specific final intelligence file."""
        if not os.path.exists(self.target_file):
            # Fallback check: if the directory exists but file is missing
            if not os.path.exists(self.storage_path):
                os.makedirs(self.storage_path, exist_ok=True)
            return None
        return self.target_file

    def process_report(self):
        report_path = self.get_report()
        if not report_path:
            print(f"[-] Target file not found: {self.target_file}")
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
        indicators = data.get("indicators", [])
        if not indicators:
            print("[!] No indicators found inside the JSON file.")
            return

        for indicator in indicators:
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

        # Save back to the SAME file (In-place update)
        with open(report_path, 'w') as f:
            json.dump(data, f, indent=4)
        
        print(f"[+] Enrichment Complete. Updated {enriched_count} new indicators.")

    def enrich_ip(self, ip):
        """Coordinates multiple IP lookups including potential clearweb feeds."""
        res = {}
        try:
            # Calls the GeoIPEnricher class
            res["geo"] = self.geoip.get_data(ip)
            
            # DRY RUN HOOK: Clearweb Feed Simulation
            # This is where we will hook in your feed data
            res["clearweb_context"] = {
                "source": "OSINT_Feed_DryRun",
                "last_seen": datetime.now().isoformat(),
                "status": "active_threat" # Placeholder for your dry run logic
            }
        except Exception as e:
            res["error"] = f"GeoIP Error: {str(e)}"
        return res

    def enrich_domain(self, domain):
        """Coordinates domain lookups"""
        res = {}
        try:
            res["whois"] = self.whois.get_data(domain)
        except Exception as e:
            res["error"] = f"Whois Error: {str(e)}"
        return res

if __name__ == "__main__":
    manager = EnrichmentManager()
    manager.process_report()