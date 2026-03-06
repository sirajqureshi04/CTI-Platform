import requests

class IPProvider:

    def __init__(self):

        self.api = "https://api.abuseipdb.com/api/v2/check"
        self.key = ""

    def enrich(self, ioc):

        ip = ioc["value"]

        try:

            headers = {
                "Key": self.key,
                "Accept": "application/json"
            }

            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90
            }

            r = requests.get(self.api, headers=headers, params=params)

            data = r.json()

            ioc["enrichment"] = data.get("data", {})

        except Exception as e:

            ioc["enrichment"] = {"error": str(e)}

        return ioc