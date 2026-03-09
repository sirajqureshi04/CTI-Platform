import requests
from functools import lru_cache


class CVEProvider:

    def __init__(self):

        self.api = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        # persistent session for connection pooling
        self.session = requests.Session()

    @lru_cache(maxsize=10000)
    def lookup_cve(self, cve_id):

        r = self.session.get(
            self.api,
            params={"cveId": cve_id},
            timeout=5
        )

        r.raise_for_status()

        data = r.json()

        vulns = data.get("vulnerabilities", [])

        if not vulns:
            return None

        cve = vulns[0].get("cve", {})

        descriptions = cve.get("descriptions", [])

        description = None

        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value")
                break

        metrics = cve.get("metrics", {})

        cvss_score = None
        severity = None

        if "cvssMetricV31" in metrics:

            cvss = metrics["cvssMetricV31"][0]["cvssData"]

            cvss_score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity")

        elif "cvssMetricV30" in metrics:

            cvss = metrics["cvssMetricV30"][0]["cvssData"]

            cvss_score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity")

        elif "cvssMetricV2" in metrics:

            cvss = metrics["cvssMetricV2"][0]["cvssData"]

            cvss_score = cvss.get("baseScore")
            severity = "UNKNOWN"

        return {
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "source": "NVD"
        }

    def enrich(self, ioc):

        cve_id = ioc.get("value")

        try:

            result = self.lookup_cve(cve_id)

            if result:
                ioc["enrichment"] = result

        except Exception as e:

            ioc["enrichment"] = {"error": str(e)}

        return ioc