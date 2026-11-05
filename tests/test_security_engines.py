"""
Unit tests for MailShield AI security engines
"""
import unittest
from core.ml_detector import PhishingDetector
from core.header_analyzer import HeaderAnalyzer, levenshtein_distance
from core.url_scanner import URLScanner
from core.attachment_scanner import AttachmentScanner
from core.crypto_suite import CryptoSuite
from core.aggregator import SecurityAggregator

class TestMailShieldSecurity(unittest.TestCase):
    def setUp(self):
        self.ml_detector = PhishingDetector()
        self.header_analyzer = HeaderAnalyzer()
        self.url_scanner = URLScanner()
        self.attachment_scanner = AttachmentScanner()
        self.aggregator = SecurityAggregator()

    def test_ml_phishing_detection(self):
        benign_text = "Hi team, please find attached the meeting minutes for yesterday's sprint planning."
        benign_res = self.ml_detector.analyze(benign_text)
        self.assertFalse(benign_res["is_phishing"])
        self.assertLess(benign_res["confidence_score"], 50.0)

        phish_text = "URGENT: Your PayPal account has been suspended! Verify your identity immediately or funds will be seized within 24 hours."
        phish_res = self.ml_detector.analyze(phish_text)
        self.assertTrue(phish_res["is_phishing"])
        self.assertGreater(phish_res["confidence_score"], 50.0)
        self.assertGreater(len(phish_res["urgency_triggers"]), 0)

    def test_header_spoofing_analysis(self):
        # Genuine email
        genuine_res = self.header_analyzer.analyze(
            from_header='"Google Support" <support@google.com>',
            auth_results="spf=pass dkim=pass dmarc=pass"
        )
        self.assertFalse(genuine_res["is_spoofed"])
        self.assertEqual(genuine_res["spf_status"], "PASS")

        # Display name spoofing
        spoofed_res = self.header_analyzer.analyze(
            from_header='"PayPal Security Team" <security@paypa1-update.xyz>',
            auth_results="spf=fail dkim=fail dmarc=fail"
        )
        self.assertTrue(spoofed_res["is_spoofed"])
        self.assertGreater(spoofed_res["spoof_score"], 60)
        self.assertTrue(any(a["type"] in ["DISPLAY_NAME_SPOOFING", "TYPOSQUATTING_DOMAIN"] for a in spoofed_res["alerts"]))

    def test_url_scanner(self):
        clean_text = "Visit our docs at https://github.com/example/project for more information."
        clean_res = self.url_scanner.scan(clean_text)
        self.assertEqual(clean_res["suspicious_urls"], 0)

        # Deceptive anchor + IP URL
        phish_text = '<a href="http://192.168.1.50/login">https://paypal.com/signin</a>'
        phish_res = self.url_scanner.scan(phish_text)
        self.assertGreater(phish_res["suspicious_urls"], 0)
        self.assertGreater(phish_res["max_url_risk"], 70)

    def test_attachment_scanner(self):
        safe_att = self.attachment_scanner.inspect_attachment("Quarterly_Report.pdf")
        self.assertFalse(safe_att["is_dangerous"])

        # Double extension exploit
        bad_att = self.attachment_scanner.inspect_attachment("Invoice_Payment.pdf.exe")
        self.assertTrue(bad_att["is_dangerous"])
        self.assertTrue(bad_att["is_double_extension"])
        self.assertGreater(bad_att["risk_score"], 80)

    def test_crypto_suite(self):
        # Generate keypair
        keypair = CryptoSuite.generate_keypair()
        self.assertIn("BEGIN PUBLIC KEY", keypair["public_key"])
        self.assertIn("BEGIN PRIVATE KEY", keypair["private_key"])

        message = "CONFIDENTIAL: Acquisition terms for project Apollo."

        # Encrypt and Decrypt
        encrypted = CryptoSuite.encrypt_message(message, keypair["public_key"])
        decrypted = CryptoSuite.decrypt_message(encrypted, keypair["private_key"])
        self.assertEqual(decrypted, message)

        # Digital Signature and Verification
        signature = CryptoSuite.sign_message(message, keypair["private_key"])
        verify_valid = CryptoSuite.verify_signature(message, signature, keypair["public_key"])
        self.assertTrue(verify_valid["valid"])

        # Tampered message check
        tampered_msg = message + "!"
        verify_tampered = CryptoSuite.verify_signature(tampered_msg, signature, keypair["public_key"])
        self.assertFalse(verify_tampered["valid"])

    def test_aggregator_end_to_end(self):
        # High-risk phishing email
        res = self.aggregator.analyze_email(
            subject="URGENT: Your account has been compromised",
            sender='"PayPal Security" <alert@paypa1-security.xyz>',
            body='Please click here immediately: <a href="http://185.220.101.5/verify">https://paypal.com/login</a> to unlock your account within 24 hours.',
            auth_results="spf=fail dkim=fail dmarc=fail",
            attachments=["Security_Patch.pdf.exe"]
        )
        self.assertEqual(res["verdict"], "QUARANTINE")
        self.assertGreater(res["threat_score"], 80)
        self.assertIn(res["threat_level"], ["HIGH", "CRITICAL"])

if __name__ == '__main__':
    unittest.main()
