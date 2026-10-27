# Phishing URL Detector

**BharatCares × IBM SkillsBuild — Cyber Security Project**

A lightweight, explainable command-line tool that analyses a URL and tells you whether it looks **SAFE**, **SUSPICIOUS** or **PHISHING**, along with the exact reasons behind the verdict.

---

## Why this project?

Phishing is one of the most common cyber attacks in India, often arriving as fake bank KYC, UPI/OTP, courier or "prize" links over SMS and WhatsApp. Most users cannot tell a fake link from a real one at a glance. This tool automates the checks a security analyst would do by eye and shows its working, so it is useful for learning as well as for screening.

## Features

- Pure Python, standard library only. No installs, no API keys, works offline.
- 14 independent checks, each with a weighted score (0–100 total).
- Explainable output: every point added is listed with a reason.
- Detects typosquatting and leetspeak look-alikes (e.g. `paypa1`, `faceb00k`) using edit distance.
- Detects brands used as a decoy subdomain (e.g. `amazon.account-verify.xyz`).
- Single URL, batch file or interactive mode.

## Detection checks

| # | Check | Why it matters |
|---|-------|----------------|
| 1 | Not HTTPS | No transport encryption |
| 2 | IP address as host | Legitimate sites use domain names |
| 3 | `@` in URL | Browser ignores text before `@`, hiding the real host |
| 4 | URL length | Long URLs hide the true domain |
| 5 | Excess subdomains | Used to bury the fake domain |
| 6 | Hyphens / digits in domain | Common in throw-away domains |
| 7 | High-risk TLD | `.tk`, `.xyz`, `.top`, etc. are heavily abused |
| 8 | URL shorteners | Hide the destination |
| 9 | Suspicious keywords | `login`, `verify`, `kyc`, `otp`, `refund`... |
| 10 | Brand impersonation | Typosquatting, embedded brand, brand-as-subdomain |
| 11 | Obfuscation | Punycode (`xn--`), heavy `%` encoding, `//` in path |
| 12 | Non-standard port | Unusual for public websites |
| 13 | High-entropy domain | Randomly generated names |
| 14 | Many query parameters | Tracking / redirect abuse |

**Verdict thresholds:** `0–24` SAFE · `25–49` SUSPICIOUS · `50–100` PHISHING

## Installation

```bash
git clone <your-repo-url>
cd phishing-url-detector
python --version        # needs Python 3.8+
pip install -r requirements.txt   # optional; the tool itself needs nothing extra
```

## Usage

```bash
# 1. Analyse one URL
python phishing_detector.py "http://secure-login.paypa1.com/verify?account=1"

# 2. Analyse many URLs from a file (one per line, '#' for comments)
python phishing_detector.py -f sample_urls.txt

# 3. Interactive mode
python phishing_detector.py
```

### Example output

```
[X] http://secure-login.paypa1.com/verify?account=1
    Risk score : 65/100
    Verdict    : PHISHING
    Reasons    :
      +10  Connection is not HTTPS
      +20  Suspicious keywords: login, verify, secure, account
      +35  Look-alike of 'paypal' (typosquatting: 'paypa1')
```

A full run over the bundled samples is saved in `sample_output.txt`.

## Project structure

```
.
├── phishing_detector.py   # main source code
├── requirements.txt       # dependencies
├── sample_urls.txt        # test URLs (safe + phishing)
├── sample_output.txt      # recorded output for the samples
├── Project_Report.pdf     # full project report
└── README.md
```

## How it works

1. **Normalise** the URL (add a scheme if missing) and parse it.
2. **Extract** host, subdomains, registered domain, TLD, path, query and port.
3. **Run checks**; each adds weighted points and a human-readable reason.
4. **Sum** the points (capped at 100) and map the score to a verdict.

## Limitations

- Rule-based, so it can miss brand-new attack patterns and can flag odd-looking legitimate sites.
- It does not fetch the page, check domain age, or query blocklists such as Google Safe Browsing or PhishTank.
- The brand list is small and focused on global and Indian services; extend `TRUSTED_BRANDS` for your needs.
- Treat the result as decision support, not proof.

## Future improvements

- Machine-learning classifier trained on a labelled URL dataset.
- WHOIS domain-age and SSL certificate checks.
- Integration with PhishTank / Safe Browsing APIs.
- Browser extension or Flask web interface.

## Safety note

The tool only analyses the **text** of a URL and never visits it, so it is safe to test with suspicious links. Do not open phishing links in a browser.

## Author

Chhitiz Srivastava — BharatCares × IBM SkillsBuild, Cyber Security

## License

MIT — free to use and modify for learning purposes.
