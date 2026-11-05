"""
Integration tests for Flask API endpoints
"""
import unittest
import json
import io
from app import app

class TestAPIEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_index_page(self):
        res = self.client.get('/')
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"MailShield", res.data)

    def test_samples_api(self):
        res = self.client.get('/api/samples')
        self.assertEqual(res.status_code, 200)
        samples = res.get_json()
        self.assertEqual(len(samples), 4)

        # Load sample 2 (PayPal Phishing)
        s2 = self.client.get('/api/samples/2')
        self.assertEqual(s2.status_code, 200)
        data = s2.get_json()
        self.assertIn("PayPal", data["sender"])

    def test_analyze_api_json(self):
        payload = {
            "sender": '"PayPal Security" <alert@paypa1-update.xyz>',
            "subject": "URGENT: Account locked",
            "body": 'Click here: <a href="http://192.168.1.1/login">https://paypal.com/signin</a> immediately',
            "auth_results": "spf=fail dkim=fail dmarc=fail",
            "attachments": "invoice.pdf.exe"
        }
        res = self.client.post('/api/analyze',
                               data=json.dumps(payload),
                               content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["verdict"], "QUARANTINE")
        self.assertGreater(data["threat_score"], 80)

    def test_crypto_api(self):
        # 1. Generate keys
        res = self.client.post('/api/crypto/generate-keys')
        self.assertEqual(res.status_code, 200)
        keys = res.get_json()
        self.assertIn("BEGIN PUBLIC KEY", keys["public_key"])

        # 2. Encrypt & Decrypt
        enc_res = self.client.post('/api/crypto/encrypt',
                                   data=json.dumps({
                                       "plaintext": "Top Secret Data",
                                       "public_key": keys["public_key"]
                                   }),
                                   content_type='application/json')
        self.assertEqual(enc_res.status_code, 200)
        ciphertext = enc_res.get_json()["ciphertext"]

        dec_res = self.client.post('/api/crypto/decrypt',
                                   data=json.dumps({
                                       "ciphertext": ciphertext,
                                       "private_key": keys["private_key"]
                                   }),
                                   content_type='application/json')
        self.assertEqual(dec_res.status_code, 200)
        self.assertEqual(dec_res.get_json()["plaintext"], "Top Secret Data")

        # 3. Sign & Verify
        sign_res = self.client.post('/api/crypto/sign',
                                    data=json.dumps({
                                        "message": "Approved payment",
                                        "private_key": keys["private_key"]
                                    }),
                                    content_type='application/json')
        self.assertEqual(sign_res.status_code, 200)
        sig = sign_res.get_json()["signature"]

        verify_res = self.client.post('/api/crypto/verify',
                                      data=json.dumps({
                                          "message": "Approved payment",
                                          "signature": sig,
                                          "public_key": keys["public_key"]
                                      }),
                                      content_type='application/json')
        self.assertEqual(verify_res.status_code, 200)
        self.assertTrue(verify_res.get_json()["valid"])

if __name__ == '__main__':
    unittest.main()
