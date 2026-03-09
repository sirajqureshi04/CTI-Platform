import requests
from functools import lru_cache

class IPProvider:

    def __init__(self):

        self.api = "https://api.abuseipdb.com/api/v2/check"
        self.key = ""

        # persistent session = connection pooling
        self.session = requests.Session()

        self.headers = {
            "Key": self.key,
            "Accept": "application/json"
        }

    @lru_cache(maxsize=10000)
    def lookup_ip(self, ip):

        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }

        r = self.session.get(
            self.api,
            headers=self.headers,
            params=params,
            timeout=5
        )

        r.raise_for_status()

        data = r.json().get("data", {})

        # keep only useful fields
        return {
            "abuse_score": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports"),
            "last_reported": data.get("lastReportedAt"),
        }

    def enrich(self, ioc):

        ip = ioc.get("value")

        try:
            ioc["enrichment"] = self.lookup_ip(ip)

        except Exception as e:

            ioc["enrichment"] = {"error": str(e)}

        return ioc