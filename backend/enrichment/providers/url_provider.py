from functools import lru_cache
from backend.utils.web_scraper import OSINTScraper


class URLProvider:

    def __init__(self):
        pass

    @lru_cache(maxsize=5000)
    def scrape_url(self, url):

        scraper = OSINTScraper()  # thread-safe instance per call

        try:

            scraped = scraper.scrape(url)

            return scraped

        except Exception:

            return []

    def enrich(self, ioc):

        url = ioc.get("value")

        try:

            scraped = self.scrape_url(url)

            ioc["enrichment"] = {
                "scraped_iocs": scraped
            }

        except Exception as e:

            ioc["enrichment"] = {"error": str(e)}

        return ioc