"""
Hash Generator
--------------
Generates MD5, SHA1, and SHA256 hashes for a file or a text string. Used
for verifying file integrity and generating IOC hash values for threat
intelligence documentation.

Usage:
    python hash_generator.py --file /path/to/file
    python hash_generator.py --text "some string"
"""

import argparse
import hashlib


def hash_bytes(data: bytes) -> dict:
    return {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA1": hashlib.sha1(data).hexdigest(),
        "SHA256": hashlib.sha256(data).hexdigest(),
    }


def hash_file(path: str, chunk_size=8192) -> dict:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"MD5": md5.hexdigest(), "SHA1": sha1.hexdigest(), "SHA256": sha256.hexdigest()}


def print_hashes(source, hashes):
    print("=" * 60)
    print(f"HASHES FOR: {source}")
    print("=" * 60)
    for algo, value in hashes.items():
        print(f"{algo:<8}: {value}")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate MD5/SHA1/SHA256 hashes")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="Path to a file to hash")
    group.add_argument("--text", help="Text string to hash")
    args = parser.parse_args()

    if args.file:
        print_hashes(args.file, hash_file(args.file))
    else:
        print_hashes(f'"{args.text}"', hash_bytes(args.text.encode("utf-8")))
