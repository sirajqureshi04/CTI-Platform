import socket
from functools import lru_cache


class DomainProvider:

    @lru_cache(maxsize=10000)
    def resolve_domain(self, domain):

        try:

            # get all IPs associated with domain
            _, _, ip_list = socket.gethostbyname_ex(domain)

            return ip_list

        except socket.gaierror:

            return []

    def enrich(self, ioc):

        domain = ioc.get("value")

        try:

            ips = self.resolve_domain(domain)

            ioc["enrichment"] = {
                "resolved_ips": ips
            }

        except Exception as e:

            ioc["enrichment"] = {
                "resolved_ips": [],
                "error": str(e)
            }

        return ioc