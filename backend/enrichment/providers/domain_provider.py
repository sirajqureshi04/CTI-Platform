import socket

class DomainProvider:

    def enrich(self, ioc):

        domain = ioc["value"]

        try:

            ip = socket.gethostbyname(domain)

            ioc["enrichment"] = {
                "resolved_ip": ip
            }

        except:

            ioc["enrichment"] = {
                "resolved_ip": None
            }

        return ioc