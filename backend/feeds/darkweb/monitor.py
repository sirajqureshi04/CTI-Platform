from stem import Signal
from stem.control import Controller
import requests
import time


class RansomwareMonitorFeed:
    """
    Dark web ransomware monitor feed.
    Fetches .onion victim pages using Tor and refreshes circuit if blocked.
    """

    def __init__(self, config: dict, logger):
        self.config = config
        self.logger = logger

        # Session configured for Tor SOCKS proxy
        self.session = requests.Session()
        self.session.proxies = {
            "http": "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050",
        }

    # ---------------------------------------------------------
    # Tor Circuit Refresh
    # ---------------------------------------------------------
    def _refresh_tor_circuit(self):
        """
        Forces Tor to get a new IP/Circuit to bypass blocks.
        Requires ControlPort 9051 enabled in torrc.
        """
        try:
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()  # Uses CookieAuth
                controller.signal(Signal.NEWNYM)

            self.logger.info("Tor circuit refreshed. New identity requested.")
            time.sleep(5)  # Allow Tor to establish new circuit

        except Exception as e:
            self.logger.error(f"Could not refresh Tor circuit: {e}")

    # ---------------------------------------------------------
    # Fetch Dark Web Sources
    # ---------------------------------------------------------
    def fetch(self) -> dict:
        """
        Fetch ransomware victim data from configured onion sources.
        Retries once with Tor circuit refresh on failure.
        """
        results = {"detections": {}}
        sources = self.config.get("sources", {})

        for name, url in sources.items():
            success = False

            for attempt in range(2):  # Try twice (normal + after refresh)
                try:
                    response = self.session.get(url, timeout=90)

                    if response.status_code == 200:
                        victims = self._parse_victims(response.text, name)

                        results["detections"][name] = {
                            "url": url,
                            "count": len(victims),
                            "status_code": 200,
                            "victims": victims,
                        }

                        success = True
                        break

                    else:
                        self.logger.warning(
                            f"{name} returned status {response.status_code}"
                        )

                except Exception as e:
                    self.logger.warning(
                        f"Attempt {attempt + 1} failed for {name}: {e}"
                    )

                # Refresh Tor before retry
                if attempt == 0:
                    self._refresh_tor_circuit()

            if not success:
                results["detections"][name] = {
                    "url": url,
                    "count": 0,
                    "status_code": "FAILED",
                    "victims": [],
                }

        return results

    # ---------------------------------------------------------
    # Victim Parser Placeholder
    # ---------------------------------------------------------
    def _parse_victims(self, html: str, source_name: str):
        """
        Parse victim entries from HTML.
        Implement your custom parsing logic here.
        """
        return []