"""
Benign network telemetry test.
Resolves a known safe domain and makes a harmless HTTP request.
"""
import socket
import urllib.request

# Safe domains that are highly unlikely to be blocked
DOMAINS = ["www.example.com", "www.microsoft.com", "www.google.com"]

def main():
    print("[dns] resolving domains...")
    for domain in DOMAINS:
        try:
            ip = socket.gethostbyname(domain)
            print(f"[dns] {domain} -> {ip}")
        except Exception as exc:
            print(f"[dns] failed to resolve {domain}: {exc}")

    print("[http] making HTTP request...")
    try:
        req = urllib.request.Request(
            "https://www.example.com/",
            headers={"User-Agent": "SandboxTelemetry/1.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[http] status: {resp.status}, bytes: {len(resp.read())}")
    except Exception as exc:
        print(f"[http] request failed: {exc}")

if __name__ == "__main__":
    main()
