import requests

class CVEProvider:

    def __init__(self):

        self.api = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def enrich(self, ioc):

        cve_id = ioc.get("value")

        try:

            r = requests.get(
                f"{self.api}?cveId={cve_id}",
                timeout=10
            )

            if r.status_code != 200:
                return ioc

            data = r.json()

            vulns = data.get("vulnerabilities", [])

            if not vulns:
                return ioc

            cve = vulns[0]["cve"]

            description = cve["descriptions"][0]["value"]

            metrics = cve.get("metrics", {})

            cvss_score = None

            if "cvssMetricV31" in metrics:
                cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

            ioc["enrichment"] = {

                "description": description,
                "cvss_score": cvss_score,
                "source": "NVD"
            }

        except Exception as e:

            ioc["enrichment"] = {"error": str(e)}

        return ioc