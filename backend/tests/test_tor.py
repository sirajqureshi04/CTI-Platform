from backend.core.tor_client import TorHTTPClient

def test_connection():
    client = TorHTTPClient()
    try:
        # This URL confirms if you are using Tor
        response = client.get("https://check.torproject.org/")
        if "Congratulations" in response.text:
            print("✅ Tor Circuit Verified: You are connected via Tor.")
        else:
            print("❌ Proxy is active but NOT routing through Tor.")
    except Exception as e:
        print(f"💥 Connection Failed: Ensure Tor service is running on 9050. Error: {e}")

if __name__ == "__main__":
    test_connection()