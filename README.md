# Phishing Email Detector

A fully offline, dependency-light Python tool that analyses emails and flags suspicious patterns commonly used in phishing attacks.

---

## Features

| Check | What it looks for |
|---|---|
| **Sender spoofing** | Display-name ≠ actual domain, brand names in free-email addresses |
| **Suspicious TLDs** | `.xyz`, `.tk`, `.top`, `.click`, and 10 others |
| **URL analysis** | IP-based links, brand-in-path tricks, homograph domains, URL shorteners |
| **Urgency language** | 20+ patterns: "act now", "account suspended", "limited time", etc. |
| **Credential harvesting** | Requests for passwords, SSN, credit card numbers |
| **Brand impersonation** | PayPal, Amazon, Apple, Microsoft, Google, banks, and more |
| **HTML obfuscation** | Hidden elements, HTML entity abuse, URL-encoded text |
| **Header anomalies** | Reply-To ≠ From domain |

Produces a **risk score (0–100)** and a **risk level**: `SAFE / LOW / MEDIUM / HIGH / CRITICAL`.

---

## Project structure

```
phishing_detector/
├── detector.py   # Core analysis engine (no external deps)
├── cli.py        # Interactive terminal interface
├── tests.py      # Unit tests (stdlib only)
└── README.md
```

---

## Requirements

- Python 3.10+
- [`rich`](https://github.com/Textualize/rich) *(optional — for coloured output)*

```bash
pip install rich          # optional but recommended
```

---

## Usage

### Interactive CLI

```bash
python cli.py
```

You'll see a menu:

```
[1]  Analyse email — manual input (paste fields)
[2]  Analyse .eml file
[3]  Run built-in demo examples
[4]  Quit
```

**Manual input** — paste the sender, subject, and body directly.

**.eml file** — point it at any raw email file saved from your mail client.

**Demo mode** — runs 4 built-in examples ranging from a clean newsletter to a prize scam.

---

### Use as a library

```python
from detector import PhishingDetector

d = PhishingDetector()

# From individual fields
report = d.analyze_fields(
    subject="URGENT: Verify your PayPal account",
    sender='"PayPal" <billing@paypa1-secure.xyz>',
    body="Click here now: http://bit.ly/paypal-verify  Enter your password.",
)

print(report.risk_level)     # HIGH
print(report.risk_score)     # e.g. 75
for flag in report.flags:
    print(f"[{flag.severity}] {flag.category}: {flag.description}")

# From a raw .eml string
with open("email.eml") as f:
    report = d.analyze_raw(f.read())

# Export to JSON
import json
print(json.dumps(report.to_dict(), indent=2))
```

---

### Run tests

```bash
python tests.py
```

All 16 tests use the standard library only (`unittest`).

---

## Risk levels

| Level | Score | Meaning |
|---|---|---|
| SAFE | 0 | No issues detected |
| LOW | 1–20 | Minor signals, probably fine |
| MEDIUM | 21–45 | Some suspicious patterns — review carefully |
| HIGH | 46–70 | Multiple strong indicators of phishing |
| CRITICAL | 71–100 | Almost certainly a phishing attempt |

---

## Saving reports

After every analysis you're asked whether to save the result as JSON. Reports contain: timestamp, sender, subject, risk score, risk level, all flags (with evidence), extracted URLs, and a plain-English summary.

---

## Limitations

- This tool uses **static pattern matching** only — no live DNS/WHOIS/VirusTotal lookups.
- It will not catch every phishing email, and may occasionally flag legitimate marketing emails as medium risk.
- Always use this as one layer of a broader email security strategy.

---

## Educational purpose

This project was built to help people understand how phishing emails are constructed, what red flags to look for, and how automated detection systems work at a basic level. It does not send emails or connect to any network.
