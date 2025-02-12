"""
tests.py — Unit tests for the phishing detection engine.
Run with:  python tests.py
"""

import unittest
from detector import PhishingDetector


class TestPhishingDetector(unittest.TestCase):

    def setUp(self):
        self.d = PhishingDetector()

    # ── safe email ────────────────────────────────────────────────────────────

    def test_safe_email(self):
        r = self.d.analyze_fields(
            subject="Your weekly Medium digest",
            sender="newsletter@medium.com",
            body="Hi, here are your top stories this week. https://medium.com/story",
        )
        self.assertIn(r.risk_level, ("SAFE", "LOW"))
        self.assertLessEqual(r.risk_score, 20)

    # ── sender spoofing ───────────────────────────────────────────────────────

    def test_display_name_spoof(self):
        r = self.d.analyze_fields(
            subject="Account alert",
            sender='"PayPal Support" <noreply@random-domain.com>',
            body="Please verify your account.",
        )
        categories = [f.category for f in r.flags]
        self.assertIn("Sender", categories)
        sevs = [f.severity for f in r.flags if f.category == "Sender"]
        self.assertIn("HIGH", sevs)

    def test_free_email_brand_spoof(self):
        r = self.d.analyze_fields(
            subject="Amazon security alert",
            sender="Amazon <amazon-security@gmail.com>",
            body="Your account is at risk.",
        )
        sender_flags = [f for f in r.flags if f.category == "Sender"]
        self.assertTrue(len(sender_flags) > 0)

    def test_suspicious_tld_sender(self):
        r = self.d.analyze_fields(
            subject="Hello",
            sender="support@company.xyz",
            body="Just checking in.",
        )
        sender_flags = [f for f in r.flags if f.category == "Sender"]
        self.assertTrue(len(sender_flags) > 0)

    # ── subject line ──────────────────────────────────────────────────────────

    def test_urgent_subject(self):
        r = self.d.analyze_fields(
            subject="URGENT: Verify your account immediately!!!",
            sender="test@example.com",
            body="Please act now.",
        )
        subj_flags = [f for f in r.flags if f.category == "Subject"]
        self.assertTrue(len(subj_flags) > 0)

    def test_normal_subject(self):
        r = self.d.analyze_fields(
            subject="Meeting notes from Tuesday",
            sender="colleague@company.com",
            body="Here are the notes from our meeting.",
        )
        subj_flags = [f for f in r.flags if f.category == "Subject"]
        self.assertEqual(len(subj_flags), 0)

    # ── URLs ──────────────────────────────────────────────────────────────────

    def test_ip_url_flagged(self):
        r = self.d.analyze_fields(
            subject="Test",
            sender="x@x.com",
            body="Click here: http://192.168.1.100/login",
        )
        url_flags = [f for f in r.flags if f.category == "URL"]
        self.assertTrue(any(f.severity == "HIGH" for f in url_flags))

    def test_brand_in_url_path(self):
        r = self.d.analyze_fields(
            subject="Your PayPal account",
            sender="billing@paypal-secure.ru",
            body="Login at http://secure-paypal-account.xyz/login",
        )
        url_flags = [f for f in r.flags if f.category == "URL"]
        self.assertTrue(len(url_flags) > 0)

    def test_shortened_url(self):
        r = self.d.analyze_fields(
            subject="Check this",
            sender="someone@somewhere.com",
            body="See this link: https://bit.ly/3xAb12Q",
        )
        url_flags = [f for f in r.flags if f.category == "URL"]
        self.assertTrue(len(url_flags) > 0)

    def test_legitimate_url(self):
        r = self.d.analyze_fields(
            subject="Read our blog",
            sender="team@company.com",
            body="Visit https://company.com/blog for more info.",
        )
        # Should have no HIGH URL flags
        high_url = [f for f in r.flags if f.category == "URL" and f.severity == "HIGH"]
        self.assertEqual(len(high_url), 0)

    # ── credential harvesting ─────────────────────────────────────────────────

    def test_credential_request(self):
        r = self.d.analyze_fields(
            subject="Update required",
            sender="support@bank.com",
            body="Please enter your password and social security number to verify your identity.",
        )
        cred_flags = [f for f in r.flags if f.category == "Credential Harvesting"]
        self.assertTrue(len(cred_flags) > 0)

    # ── risk score ordering ───────────────────────────────────────────────────

    def test_phish_scores_higher_than_legit(self):
        legit = self.d.analyze_fields(
            subject="Meeting reminder",
            sender="boss@company.com",
            body="Don't forget our 3pm call.",
        )
        phish = self.d.analyze_fields(
            subject="URGENT: Your PayPal account suspended!!!",
            sender='"PayPal" <billing@paypa1.xyz>',
            body=(
                "Act now — click here http://paypa1-login.top/verify "
                "and enter your password and credit card number."
            ),
        )
        self.assertGreater(phish.risk_score, legit.risk_score)

    def test_critical_risk_level(self):
        r = self.d.analyze_fields(
            subject="URGENT ACTION REQUIRED: Account SUSPENDED!!!",
            sender='"PayPal Security" <alert@paypa1-secure.xyz>',
            body=(
                "Your PayPal account has been compromised. "
                "Verify immediately: http://192.168.10.5/paypal/login "
                "Enter your password, SSN, and credit card number. Limited time!"
            ),
        )
        self.assertIn(r.risk_level, ("HIGH", "CRITICAL"))
        self.assertGreater(r.risk_score, 50)

    # ── header checks ─────────────────────────────────────────────────────────

    def test_reply_to_mismatch(self):
        r = self.d.analyze_fields(
            subject="Hello",
            sender="legit@company.com",
            body="Just checking in.",
            headers={
                "From": "legit@company.com",
                "Reply-To": "attacker@evil.tk",
            },
        )
        hdr_flags = [f for f in r.flags if f.category == "Headers"]
        self.assertTrue(len(hdr_flags) > 0)

    # ── raw email parsing ─────────────────────────────────────────────────────

    def test_raw_email_parse(self):
        raw = (
            "From: Attacker <phish@evil.tk>\r\n"
            "To: victim@company.com\r\n"
            "Subject: URGENT: Your account is suspended!\r\n"
            "Content-Type: text/plain\r\n\r\n"
            "Click here immediately: http://bit.ly/fakelink\n"
            "Enter your password to restore access."
        )
        r = self.d.analyze_raw(raw)
        self.assertGreater(r.risk_score, 10)
        self.assertEqual(r.subject, "URGENT: Your account is suspended!")

    # ── report serialisation ──────────────────────────────────────────────────

    def test_report_to_dict(self):
        r = self.d.analyze_fields(
            subject="Test", sender="a@b.com", body="Hello world"
        )
        d = r.to_dict()
        for key in ("timestamp", "subject", "sender", "risk_score", "risk_level", "flags", "urls", "summary"):
            self.assertIn(key, d)


if __name__ == "__main__":
    unittest.main(verbosity=2)
