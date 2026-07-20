"""
IOC Extractor
-------------
Extracts common Indicators of Compromise (IPv4 addresses, domains, email
addresses, and MD5/SHA1/SHA256 hashes) from a block of text using regular
expressions. Useful for quickly pulling structured IOCs out of incident
notes, emails, or log excerpts for a threat intel writeup.

Usage:
    python ioc_extractor.py --file data/sample_incident_notes.txt
"""

import argparse
import re

PATTERNS = {
    "IPv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "Domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
    "Email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "MD5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "SHA1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "SHA256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}


def extract_iocs(text):
    results = {}
    emails = set(PATTERNS["Email"].findall(text))
    ips = set(PATTERNS["IPv4"].findall(text))
    hashes256 = set(PATTERNS["SHA256"].findall(text))
    hashes1 = set(PATTERNS["SHA1"].findall(text)) - hashes256
    hashes_md5 = set(PATTERNS["MD5"].findall(text)) - hashes1 - hashes256

    # Domains: exclude anything that's actually part of an email or an IP
    all_domains = set(PATTERNS["Domain"].findall(text))
    email_domains = {e.split("@")[1] for e in emails}
    domains = {d for d in all_domains if d not in email_domains and not PATTERNS["IPv4"].fullmatch(d)}

    results["IPv4 Addresses"] = sorted(ips)
    results["Domains"] = sorted(domains)
    results["Email Addresses"] = sorted(emails)
    results["MD5 Hashes"] = sorted(hashes_md5)
    results["SHA1 Hashes"] = sorted(hashes1)
    results["SHA256 Hashes"] = sorted(hashes256)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract IOCs from text")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="Path to a text file")
    group.add_argument("--text", help="Raw text to scan")
    args = parser.parse_args()

    content = open(args.file, encoding="utf-8").read() if args.file else args.text
    results = extract_iocs(content)

    print("=" * 60)
    print("IOC EXTRACTION RESULTS")
    print("=" * 60)
    total = 0
    for category, values in results.items():
        print(f"\n{category} ({len(values)}):")
        for v in values:
            print(f"  - {v}")
        total += len(values)
    print("\n" + "=" * 60)
    print(f"Total IOCs extracted: {total}")
