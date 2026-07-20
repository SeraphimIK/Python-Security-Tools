"""
Hash Checker
------------
Checks a file's hash (or a manually supplied hash) against a known
IOC (Indicator of Compromise) hash database, e.g. malware signatures
from threat intelligence feeds.

Usage:
    python hash_checker.py --file /path/to/file
    python hash_checker.py --hash 44d88612fea8a8f36de82e1278abb02f
"""

import argparse
import csv
import hashlib
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IOC_DB = os.path.join(BASE_DIR, "data", "known_ioc_hashes.csv")


def load_ioc_db(path):
    db = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            db[row["hash"].lower()] = row
    return db


def hash_file(path):
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return [md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()]


def check(hashes_to_check, db):
    matches = []
    for h in hashes_to_check:
        if h.lower() in db:
            matches.append(db[h.lower()])
    return matches


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check a file or hash against known IOC hashes")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="Path to a file to check")
    group.add_argument("--hash", help="A single hash value to check")
    args = parser.parse_args()

    db = load_ioc_db(IOC_DB)

    if args.file:
        candidates = hash_file(args.file)
        source = args.file
    else:
        candidates = [args.hash]
        source = args.hash

    matches = check(candidates, db)

    print("=" * 60)
    print(f"HASH CHECK: {source}")
    print("=" * 60)
    if matches:
        for m in matches:
            print(f"MATCH FOUND: {m['threat_name']}  ({m['hash_type']}, source: {m['source']})")
        print("Result: KNOWN MALICIOUS INDICATOR")
    else:
        print("No match found in known IOC database.")
        print("Result: CLEAN (against this dataset only)")
    print("=" * 60)
