#!/usr/bin/env python3
"""
Phishing URL Detector
BharatCares - IBM SkillsBuild Cyber Security Project

A rule-based, explainable phishing URL scanner. It extracts lexical and
host-based features from a URL, assigns a weighted risk score (0-100), and
classifies the URL as SAFE, SUSPICIOUS or PHISHING.

Usage:
    python phishing_detector.py "http://secure-login.paypa1.com/verify?id=1"
    python phishing_detector.py -f urls.txt
    python phishing_detector.py            # interactive mode
"""

import argparse
import ipaddress
import math
import re
import sys
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking", "confirm",
    "signin", "password", "wallet", "free", "bonus", "suspend", "unlock",
    "kyc", "otp", "refund", "prize", "lucky",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}

RISKY_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work",
    "zip", "mov", "icu", "rest", "country", "support",
}

# Brands commonly impersonated; used for look-alike detection.
TRUSTED_BRANDS = [
    "paypal", "google", "facebook", "amazon", "microsoft", "apple",
    "netflix", "instagram", "whatsapp", "sbi", "hdfc", "icici", "paytm",
    "phonepe", "flipkart", "irctc", "uidai", "ibm",
]

LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a",
                          "5": "s", "7": "t", "@": "a", "$": "s"})


def levenshtein(a: str, b: str) -> int:
    """Edit distance between two strings."""
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {c: text.count(c) for c in set(text)}
    n = len(text)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def normalise(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registered_parts(host: str):
    """Return (subdomains, domain_label, tld) using a simple heuristic."""
    parts = host.lower().split(".")
    if len(parts) < 2:
        return [], host, ""
    # Handle common two-level TLDs such as co.in, org.in, co.uk
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"} \
            and len(parts[-1]) == 2:
        return parts[:-3], parts[-3], ".".join(parts[-2:])
    return parts[:-2], parts[-2], parts[-1]


def analyse(url: str) -> dict:
    """Return dict with score, verdict and list of (points, reason)."""
    raw = url
    url = normalise(url)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    findings = []

    def add(points, reason):
        findings.append((points, reason))

    if not host:
        return {"url": raw, "score": 100, "verdict": "PHISHING",
                "findings": [(100, "Could not parse a valid hostname")]}

    if is_ip(host):
        subs, domain, tld = [], host, ""
    else:
        subs, domain, tld = registered_parts(host)

    # 1. Transport security
    if parsed.scheme != "https":
        add(10, "Connection is not HTTPS")

    # 2. IP address instead of domain
    if is_ip(host):
        add(25, "Host is a raw IP address")

    # 3. '@' trick in URL
    if "@" in parsed.netloc:
        add(25, "URL contains '@' (browser ignores text before it)")

    # 4. Length
    if len(url) > 100:
        add(10, f"Very long URL ({len(url)} chars)")
    elif len(url) > 75:
        add(5, f"Long URL ({len(url)} chars)")

    # 5. Subdomain depth
    if len(subs) >= 3:
        add(15, f"Excessive subdomains ({len(subs)})")
    elif len(subs) == 2:
        add(5, "Multiple subdomains")

    # 6. Hyphens & digits in domain
    if domain.count("-") >= 2:
        add(10, "Multiple hyphens in domain name")
    elif "-" in domain:
        add(5, "Hyphen in domain name")
    if sum(c.isdigit() for c in domain) >= 3:
        add(8, "Many digits in domain name")

    # 7. Risky TLD
    if tld.split(".")[-1] in RISKY_TLDS:
        add(15, f"High-risk TLD '.{tld}'")

    # 8. URL shorteners
    if host in SHORTENERS:
        add(25, "URL shortener hides the real destination")

    # 9. Suspicious keywords
    full = (host + parsed.path + parsed.query).lower()
    hits = [k for k in SUSPICIOUS_KEYWORDS if k in full]
    if hits:
        add(min(5 * len(hits), 20), "Suspicious keywords: " + ", ".join(hits[:6]))

    # 10. Brand look-alike / typosquatting / brand in subdomain
    cleaned = domain.translate(LEET_MAP)
    for brand in TRUSTED_BRANDS:
        if domain == brand:
            break  # genuine-looking registered domain
        if cleaned == brand or (0 < levenshtein(cleaned, brand) <= 1 and len(brand) > 4):
            add(35, f"Look-alike of '{brand}' (typosquatting: '{domain}')")
            break
        if brand in domain and domain != brand:
            add(20, f"Brand '{brand}' embedded in unrelated domain '{domain}'")
            break
        if any(brand in s for s in subs):
            add(25, f"Brand '{brand}' used as subdomain of '{domain}.{tld}'")
            break

    # 11. Encoding / obfuscation
    if "xn--" in host:
        add(20, "Punycode (possible homograph attack)")
    if parsed.path.count("%") >= 3 or parsed.query.count("%") >= 3:
        add(8, "Heavy percent-encoding")
    if "//" in parsed.path:
        add(5, "Double slash in path (redirect trick)")

    # 12. Non-standard port
    if parsed.port and parsed.port not in (80, 443):
        add(10, f"Non-standard port {parsed.port}")

    # 13. Entropy (random-looking domains)
    if len(domain) >= 8 and shannon_entropy(domain) > 3.5:
        add(10, "Domain looks randomly generated (high entropy)")

    # 14. Many special characters in query
    if len(re.findall(r"[=&?]", parsed.query)) > 6:
        add(5, "Large number of query parameters")

    score = min(sum(p for p, _ in findings), 100)
    verdict = "SAFE" if score < 25 else "SUSPICIOUS" if score < 50 else "PHISHING"
    return {"url": raw, "score": score, "verdict": verdict, "findings": findings}


def report(result: dict) -> str:
    icon = {"SAFE": "[+]", "SUSPICIOUS": "[!]", "PHISHING": "[X]"}[result["verdict"]]
    lines = [f"{icon} {result['url']}",
             f"    Risk score : {result['score']}/100",
             f"    Verdict    : {result['verdict']}"]
    if result["findings"]:
        lines.append("    Reasons    :")
        lines += [f"      +{p:<3} {r}" for p, r in result["findings"]]
    else:
        lines.append("    Reasons    : none - no red flags detected")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Rule-based phishing URL detector")
    ap.add_argument("url", nargs="?", help="URL to analyse")
    ap.add_argument("-f", "--file", help="text file with one URL per line")
    args = ap.parse_args()

    if args.url:
        urls = [args.url]
    elif args.file:
        with open(args.file, encoding="utf-8") as fh:
            urls = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    else:
        print("Phishing URL Detector - enter a URL (blank line to quit)")
        urls = []
        while True:
            try:
                line = input("URL> ").strip()
            except EOFError:
                break
            if not line:
                break
            print(report(analyse(line)))
            print()
        return

    for u in urls:
        print(report(analyse(u)))
        print()


if __name__ == "__main__":
    sys.exit(main())
