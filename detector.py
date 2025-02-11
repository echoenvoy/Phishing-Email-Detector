"""
detector.py — Core phishing analysis engine.
Runs every check and returns a structured report.
"""

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional
from email import message_from_string
from datetime import datetime


# ─── Result structures ────────────────────────────────────────────────────────

@dataclass
class Flag:
    category: str          # e.g. "URL", "Sender", "Content"
    severity: str          # "HIGH" | "MEDIUM" | "LOW"
    description: str
    evidence: str = ""


@dataclass
class AnalysisReport:
    timestamp: str
    subject: str
    sender: str
    risk_score: int                  # 0–100
    risk_level: str                  # SAFE / LOW / MEDIUM / HIGH / CRITICAL
    flags: list[Flag] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    suspicious_urls: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "subject": self.subject,
            "sender": self.sender,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "flags": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "description": f.description,
                    "evidence": f.evidence,
                }
                for f in self.flags
            ],
            "urls": self.urls,
            "suspicious_urls": self.suspicious_urls,
            "summary": self.summary,
        }


# ─── Known-bad patterns ────────────────────────────────────────────────────────

URGENT_PHRASES = [
    r"\bact\s+now\b", r"\burgent\b", r"\bimmediately\b", r"\bverify\s+your\b",
    r"\baccount\s+(suspended|locked|compromised|at\s+risk)\b",
    r"\bclick\s+here\b", r"\bconfirm\s+your\b", r"\byour\s+account\s+will\b",
    r"\bsuspicious\s+activity\b", r"\bunusual\s+(sign-?in|login|activity)\b",
    r"\bsecurity\s+alert\b", r"\bpassword\s+(expired|reset|immediately)\b",
    r"\byou\s+have\s+(won|been\s+selected)\b", r"\bcongratulations\b",
    r"\bfree\s+(gift|prize|reward|money)\b", r"\b(limited\s+time|expires?\s+soon)\b",
    r"\bfinal\s+notice\b", r"\baction\s+required\b",
]

TRUSTED_IMPERSONATION = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "instagram", "twitter", "bank", "irs", "fedex", "dhl",
    "ups", "linkedin", "dropbox", "onedrive", "wellsfargo", "chase",
    "citibank", "americanexpress",
]

SUSPICIOUS_TLD = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top",
    ".click", ".loan", ".work", ".party", ".download", ".accountant",
]

LEGIT_DOMAINS = {
    "paypal.com", "amazon.com", "apple.com", "microsoft.com",
    "google.com", "facebook.com", "netflix.com", "instagram.com",
    "twitter.com", "linkedin.com", "dropbox.com",
}

# Patterns that suggest credential harvesting
CREDENTIAL_PATTERNS = [
    r"\benter\s+your\s+(password|credentials|login|username)\b",
    r"\bprovide\s+your\b", r"\bsubmit\s+your\b",
    r"\bsocial\s+security\s+number\b", r"\bssn\b",
    r"\bcredit\s+card\b", r"\bbank\s+account\s+number\b",
    r"\bdate\s+of\s+birth\b",
]

HTML_OBFUSCATION = [
    r"&#\d+;",          # HTML entities used to hide text
    r"%[0-9a-fA-F]{2}", # URL encoding in visible text
    r"<[^>]+style\s*=\s*['\"][^'\"]*display\s*:\s*none",  # hidden elements
]


# ─── Analyser ─────────────────────────────────────────────────────────────────

class PhishingDetector:
    """
    Analyses a raw email string (or individual fields) and returns
    an AnalysisReport with risk score, risk level, and individual flags.
    """

    def __init__(self):
        self._urgent_re = [re.compile(p, re.I) for p in URGENT_PHRASES]
        self._cred_re   = [re.compile(p, re.I) for p in CREDENTIAL_PATTERNS]
        self._obf_re    = [re.compile(p, re.I) for p in HTML_OBFUSCATION]

    # ── public API ─────────────────────────────────────────────────────────────

    def analyze_raw(self, raw_email: str) -> AnalysisReport:
        """Parse a full RFC-2822 email string and analyse it."""
        msg = message_from_string(raw_email)
        subject = msg.get("Subject", "(no subject)")
        sender  = msg.get("From", "(unknown sender)")
        body    = self._extract_body(msg)
        return self._run(subject, sender, body)

    def analyze_fields(
        self,
        subject: str,
        sender: str,
        body: str,
        headers: Optional[dict] = None,
    ) -> AnalysisReport:
        """Analyse individual fields (handy for manual / paste input)."""
        return self._run(subject, sender, body, headers or {})

    # ── internal pipeline ──────────────────────────────────────────────────────

    def _run(
        self,
        subject: str,
        sender: str,
        body: str,
        headers: dict = {},
    ) -> AnalysisReport:

        flags: list[Flag] = []
        score = 0

        # 1. Sender checks
        sender_flags, sender_score = self._check_sender(sender)
        flags += sender_flags
        score += sender_score

        # 2. Subject checks
        subj_flags, subj_score = self._check_subject(subject)
        flags += subj_flags
        score += subj_score

        # 3. Body: urgent / manipulative language
        lang_flags, lang_score = self._check_language(body)
        flags += lang_flags
        score += lang_score

        # 4. Body: credential harvesting
        cred_flags, cred_score = self._check_credentials(body)
        flags += cred_flags
        score += cred_score

        # 5. URL extraction + analysis
        urls = self._extract_urls(body)
        url_flags, url_score, suspicious_urls = self._check_urls(urls, sender)
        flags += url_flags
        score += url_score

        # 6. HTML obfuscation tricks
        obf_flags, obf_score = self._check_obfuscation(body)
        flags += obf_flags
        score += obf_score

        # 7. Brand impersonation
        imp_flags, imp_score = self._check_impersonation(subject, body, sender)
        flags += imp_flags
        score += imp_score

        # 8. Header anomalies
        hdr_flags, hdr_score = self._check_headers(headers)
        flags += hdr_flags
        score += hdr_score

        score = min(score, 100)
        risk_level = self._score_to_level(score)

        report = AnalysisReport(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            subject=subject,
            sender=sender,
            risk_score=score,
            risk_level=risk_level,
            flags=flags,
            urls=urls,
            suspicious_urls=suspicious_urls,
            summary=self._build_summary(risk_level, flags),
        )
        return report

    # ── checks ─────────────────────────────────────────────────────────────────

    def _check_sender(self, sender: str):
        flags, score = [], 0

        # Display name vs actual address mismatch
        match = re.search(r'"?([^"<]+)"?\s*<([^>]+)>', sender)
        if match:
            display, address = match.group(1).strip().lower(), match.group(2).strip().lower()
            for brand in TRUSTED_IMPERSONATION:
                if brand in display and brand not in address:
                    flags.append(Flag(
                        "Sender", "HIGH",
                        f"Display name claims to be '{brand}' but email domain does not match.",
                        evidence=sender,
                    ))
                    score += 30

        # Free webmail sending "official" alerts
        free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]
        for fp in free_providers:
            if fp in sender.lower():
                for brand in TRUSTED_IMPERSONATION:
                    if brand in sender.lower():
                        flags.append(Flag(
                            "Sender", "HIGH",
                            f"Brand '{brand}' mentioned in a free-email sender address.",
                            evidence=sender,
                        ))
                        score += 25

        # Suspicious TLD in sender domain
        domain_match = re.search(r"@([\w.\-]+)", sender)
        if domain_match:
            domain = domain_match.group(1).lower()
            for tld in SUSPICIOUS_TLD:
                if domain.endswith(tld):
                    flags.append(Flag(
                        "Sender", "MEDIUM",
                        f"Sender domain uses suspicious TLD '{tld}'.",
                        evidence=domain,
                    ))
                    score += 15

        return flags, score

    def _check_subject(self, subject: str):
        flags, score = [], 0
        lower = subject.lower()

        urgent_hits = [p.pattern for p in self._urgent_re if p.search(subject)]
        if urgent_hits:
            flags.append(Flag(
                "Subject", "MEDIUM",
                "Subject line uses urgency / fear tactics.",
                evidence=", ".join(urgent_hits[:3]),
            ))
            score += 10

        # ALL CAPS words (shouting)
        caps_words = re.findall(r'\b[A-Z]{4,}\b', subject)
        if len(caps_words) >= 2:
            flags.append(Flag(
                "Subject", "LOW",
                "Multiple all-caps words — common in spam/phishing.",
                evidence=" ".join(caps_words),
            ))
            score += 5

        # Excessive punctuation
        if re.search(r'[!?]{2,}', subject):
            flags.append(Flag(
                "Subject", "LOW",
                "Excessive punctuation in subject line.",
                evidence=subject,
            ))
            score += 5

        return flags, score

    def _check_language(self, body: str):
        flags, score = [], 0
        hits = [p.pattern for p in self._urgent_re if p.search(body)]
        if len(hits) >= 3:
            flags.append(Flag(
                "Content", "HIGH",
                f"Body contains {len(hits)} urgency / manipulation phrases.",
                evidence=", ".join(hits[:5]),
            ))
            score += 20
        elif hits:
            flags.append(Flag(
                "Content", "MEDIUM",
                f"Body contains {len(hits)} urgency phrase(s).",
                evidence=", ".join(hits),
            ))
            score += 10
        return flags, score

    def _check_credentials(self, body: str):
        flags, score = [], 0
        hits = [p.pattern for p in self._cred_re if p.search(body)]
        if hits:
            flags.append(Flag(
                "Credential Harvesting", "HIGH",
                "Email asks for sensitive personal or financial information.",
                evidence=", ".join(hits),
            ))
            score += 25
        return flags, score

    def _check_urls(self, urls: list[str], sender: str):
        flags, score, suspicious = [], 0, []

        sender_domain = ""
        m = re.search(r"@([\w.\-]+)", sender)
        if m:
            sender_domain = m.group(1).lower()

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname or ""
            lower_url = url.lower()

            # IP address instead of domain
            if re.match(r"\d{1,3}(\.\d{1,3}){3}", hostname):
                flags.append(Flag("URL", "HIGH", "URL uses raw IP address.", evidence=url))
                score += 20
                suspicious.append(url)
                continue

            # Suspicious TLD
            for tld in SUSPICIOUS_TLD:
                if hostname.endswith(tld):
                    flags.append(Flag("URL", "MEDIUM", f"URL domain has suspicious TLD '{tld}'.", evidence=url))
                    score += 15
                    suspicious.append(url)

            # Brand name in URL path/subdomain but not the real domain
            for brand in TRUSTED_IMPERSONATION:
                real = f"{brand}.com"
                if brand in lower_url and real not in hostname and f"www.{real}" not in hostname:
                    flags.append(Flag(
                        "URL", "HIGH",
                        f"URL contains brand '{brand}' but is NOT the official domain.",
                        evidence=url,
                    ))
                    score += 25
                    if url not in suspicious:
                        suspicious.append(url)

            # URL shorteners
            shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.io", "rb.gy"]
            if any(s in hostname for s in shorteners):
                flags.append(Flag("URL", "MEDIUM", "URL is shortened — destination is hidden.", evidence=url))
                score += 15
                if url not in suspicious:
                    suspicious.append(url)

            # Domain mismatch with sender
            if sender_domain and hostname and sender_domain not in hostname and hostname not in sender_domain:
                # Only flag if the URL domain looks like a known brand
                for brand in TRUSTED_IMPERSONATION:
                    if brand in hostname and brand not in sender_domain:
                        flags.append(Flag(
                            "URL", "MEDIUM",
                            "Link domain doesn't match sender domain.",
                            evidence=f"sender: {sender_domain} | url: {hostname}",
                        ))
                        score += 10
                        if url not in suspicious:
                            suspicious.append(url)
                        break

            # Homograph / lookalike characters
            lookalikes = {
                "0": "o", "1": "l", "rn": "m", "vv": "w",
                "paypa1": "paypal", "micosoft": "microsoft", "arnazon": "amazon",
            }
            for fake, real_str in lookalikes.items():
                if fake in lower_url:
                    flags.append(Flag(
                        "URL", "HIGH",
                        f"Possible lookalike domain — '{fake}' may impersonate '{real_str}'.",
                        evidence=url,
                    ))
                    score += 20
                    if url not in suspicious:
                        suspicious.append(url)

        if not urls and re.search(r"click|link|button|here", "", re.I):
            pass  # no URLs to extract — not necessarily suspicious

        return flags, min(score, 40), list(dict.fromkeys(suspicious))

    def _check_obfuscation(self, body: str):
        flags, score = [], 0
        hits = [p.pattern for p in self._obf_re if p.search(body)]
        if hits:
            flags.append(Flag(
                "Obfuscation", "HIGH",
                "Email contains HTML obfuscation techniques to hide content.",
                evidence=", ".join(hits),
            ))
            score += 20
        return flags, score

    def _check_impersonation(self, subject: str, body: str, sender: str):
        flags, score = [], 0
        combined = (subject + " " + body).lower()
        sender_lower = sender.lower()

        for brand in TRUSTED_IMPERSONATION:
            if brand in combined:
                real_domain = f"{brand}.com"
                if real_domain not in sender_lower:
                    # Brand mentioned in content but sender isn't from that brand
                    flags.append(Flag(
                        "Impersonation", "HIGH",
                        f"Email references '{brand}' but sender is not from {real_domain}.",
                        evidence=f"sender: {sender}",
                    ))
                    score += 20
                    break  # one flag is enough for impersonation

        return flags, min(score, 20)

    def _check_headers(self, headers: dict):
        flags, score = [], 0

        reply_to = headers.get("Reply-To", "")
        from_addr = headers.get("From", "")

        if reply_to and from_addr:
            from_domain = re.search(r"@([\w.\-]+)", from_addr)
            reply_domain = re.search(r"@([\w.\-]+)", reply_to)
            if from_domain and reply_domain:
                if from_domain.group(1).lower() != reply_domain.group(1).lower():
                    flags.append(Flag(
                        "Headers", "MEDIUM",
                        "Reply-To domain differs from From domain — replies go elsewhere.",
                        evidence=f"From: {from_domain.group(1)} | Reply-To: {reply_domain.group(1)}",
                    ))
                    score += 15

        return flags, score

    # ── helpers ───────────────────────────────────────────────────────────────

    def _extract_body(self, msg) -> str:
        body_parts = []
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct in ("text/plain", "text/html"):
                    try:
                        body_parts.append(part.get_payload(decode=True).decode(errors="replace"))
                    except Exception:
                        pass
        else:
            try:
                body_parts.append(msg.get_payload(decode=True).decode(errors="replace"))
            except Exception:
                body_parts.append(str(msg.get_payload()))
        return "\n".join(body_parts)

    def _extract_urls(self, text: str) -> list[str]:
        pattern = r'https?://[^\s\'"<>)}\]]+'
        found = re.findall(pattern, text, re.I)
        # Also catch href= patterns
        hrefs = re.findall(r'href=["\']?(https?://[^\s\'"<>]+)', text, re.I)
        all_urls = list(dict.fromkeys(found + hrefs))  # dedup, preserve order
        return all_urls

    @staticmethod
    def _score_to_level(score: int) -> str:
        if score == 0:
            return "SAFE"
        elif score <= 20:
            return "LOW"
        elif score <= 45:
            return "MEDIUM"
        elif score <= 70:
            return "HIGH"
        else:
            return "CRITICAL"

    @staticmethod
    def _build_summary(risk_level: str, flags: list[Flag]) -> str:
        if risk_level == "SAFE":
            return "No suspicious patterns detected. This email appears legitimate."
        high = [f for f in flags if f.severity == "HIGH"]
        med  = [f for f in flags if f.severity == "MEDIUM"]
        parts = []
        if high:
            parts.append(f"{len(high)} high-severity issue(s)")
        if med:
            parts.append(f"{len(med)} medium-severity issue(s)")
        categories = list(dict.fromkeys(f.category for f in flags))
        return (
            f"Risk level {risk_level}. Found {', '.join(parts) or str(len(flags)) + ' issue(s)'}. "
            f"Affected areas: {', '.join(categories)}."
        )
