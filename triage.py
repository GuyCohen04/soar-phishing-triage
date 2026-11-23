"""Phishing triage: check a reported URL's domain against VirusTotal and return a verdict.

Usage:
    export VT_API_KEY="your-virustotal-key"
    python triage.py "http://example.com/login"
"""

import os
import sys
from urllib.parse import urlparse

import requests

VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
MALICIOUS_THRESHOLD = 3  # vendors that must flag the domain to call it malicious


def extract_domain(url: str) -> str:
    """Return the domain from a URL, e.g. http://bad.com/login -> bad.com."""
    return urlparse(url).netloc.lower()


def check_virustotal(domain: str, api_key: str) -> int:
    """Return how many VirusTotal vendors flag the domain as malicious."""
    response = requests.get(
        VT_DOMAIN_URL.format(domain=domain),
        headers={"x-apikey": api_key},
        timeout=15,
    )
    response.raise_for_status()
    stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    return stats["malicious"]


def triage(url: str, api_key: str) -> dict:
    domain = extract_domain(url)
    flagged = check_virustotal(domain, api_key)
    malicious = flagged >= MALICIOUS_THRESHOLD
    return {
        "domain": domain,
        "vendors_flagging": flagged,
        "verdict": "MALICIOUS" if malicious else "CLEAN",
        "action": "Block the domain and quarantine the email."
        if malicious
        else "No action, close the report.",
    }


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit('Usage: python triage.py "<reported URL>"')
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        sys.exit("Set the VT_API_KEY environment variable first.")

    result = triage(sys.argv[1], api_key)
    print(f"Verdict: {result['verdict']}")
    print(f"Domain: {result['domain']}")
    print(f"Vendors flagging: {result['vendors_flagging']}")
    print(f"Recommended action: {result['action']}")


if __name__ == "__main__":
    main()
