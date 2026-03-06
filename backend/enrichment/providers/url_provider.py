from backend.utils.web_scraper import OSINTScraper

class URLProvider:

    def __init__(self):

        self.scraper = OSINTScraper()

    def enrich(self, ioc):

        url = ioc["value"]

        try:

            scraped = self.scraper.scrape(url)

            ioc["enrichment"] = {
                "scraped_iocs": scraped
            }

        except Exception as e:

            ioc["enrichment"] = {"error": str(e)}

        return ioc