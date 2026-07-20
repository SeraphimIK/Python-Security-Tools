"""
Password Strength Checker
---------------------------
Evaluates password strength using a rule-based scoring model aligned with
common guidance (length, character diversity, no dictionary/common-password
matches) rather than a single "meets complexity" pass/fail, since rule-only
checks miss weak-but-technically-compliant passwords.

Scoring factors:
  + Length (longer is weighted more heavily than complexity alone)
  + Character set diversity (lowercase, uppercase, digits, symbols)
  + Not present in a common/breached password list
  + No simple sequential or repeated-character patterns

Usage:
    python password_strength_checker.py "SomePassword123!"
"""

import argparse
import os
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMMON_LIST = os.path.join(BASE_DIR, "data", "common_passwords.txt")


def load_common_passwords(path):
    with open(path, encoding="utf-8") as f:
        return {line.strip().lower() for line in f if line.strip()}


def has_sequential_or_repeated(password):
    lowered = password.lower()
    for i in range(len(lowered) - 2):
        chunk = lowered[i:i + 3]
        if len(set(chunk)) == 1:  # e.g. "aaa"
            return True
        if ord(chunk[1]) - ord(chunk[0]) == 1 and ord(chunk[2]) - ord(chunk[1]) == 1:
            return True  # e.g. "abc", "123"
    return False


def evaluate(password, common_passwords):
    score = 0
    reasons = []

    length = len(password)
    if length >= 14:
        score += 3
    elif length >= 10:
        score += 2
    elif length >= 8:
        score += 1
    else:
        reasons.append("Too short (under 8 characters)")

    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", password))
    diversity = sum([has_lower, has_upper, has_digit, has_symbol])
    score += diversity
    if diversity < 3:
        reasons.append("Limited character diversity (mix upper/lower/digits/symbols)")

    if password.lower() in common_passwords:
        score = 0
        reasons.append("Found in common/breached password list")

    if has_sequential_or_repeated(password):
        score -= 2
        reasons.append("Contains sequential or repeated characters (e.g. 'abc', '111')")

    score = max(0, score)

    if score >= 6:
        rating = "Strong"
    elif score >= 4:
        rating = "Moderate"
    else:
        rating = "Weak"

    return rating, score, reasons


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rule-based password strength checker")
    parser.add_argument("password", help="Password to evaluate")
    args = parser.parse_args()

    common = load_common_passwords(COMMON_LIST)
    rating, score, reasons = evaluate(args.password, common)

    print("=" * 60)
    print("PASSWORD STRENGTH ASSESSMENT")
    print("=" * 60)
    print(f"Rating: {rating}  (score: {score}/7)")
    if reasons:
        print("Issues:")
        for r in reasons:
            print(f"  - {r}")
    else:
        print("No issues found.")
    print("=" * 60)
