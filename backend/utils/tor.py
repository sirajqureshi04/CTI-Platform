import requests

def tor_session():
    """Returns a requests session configured for the local Tor proxy."""
    session = requests.Session()
    # Using socks5h allows DNS resolution to happen over the Tor network (critical for .onion)
    session.proxies = {
        'http':  'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    return session