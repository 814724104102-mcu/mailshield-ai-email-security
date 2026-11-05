"""
Cryptographic Suite for End-to-End Email Security
Implements RSA-2048 keypair generation, Hybrid AES-256-GCM encryption/decryption,
and RSA-PSS digital signatures for non-repudiation and tamper detection.
"""
import os
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoSuite:
    def __init__(self):
        pass

    @staticmethod
    def generate_keypair() -> dict:
        """Generate a 2048-bit RSA keypair and return as PEM strings."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        return {
            "private_key": private_pem,
            "public_key": public_pem
        }

    @staticmethod
    def encrypt_message(plaintext: str, public_key_pem: str) -> str:
        """
        Hybrid Encryption:
        1. Generates 256-bit AES key.
        2. Encrypts plaintext with AES-256-GCM.
        3. Encrypts AES key with Recipient's RSA Public Key (OAEP SHA-256).
        Returns base64 encoded JSON envelope.
        """
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))

        # Generate ephemeral 256-bit AES key and 96-bit IV
        aes_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(aes_key)
        iv = os.urandom(12)

        # Encrypt plaintext
        ciphertext_and_tag = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)

        # Encrypt AES key using RSA OAEP
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        envelope = {
            "v": 1,
            "cipher": "AES-256-GCM + RSA-2048-OAEP",
            "enc_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "payload": base64.b64encode(ciphertext_and_tag).decode('utf-8')
        }

        return base64.b64encode(json.dumps(envelope).encode('utf-8')).decode('utf-8')

    @staticmethod
    def decrypt_message(encrypted_envelope_b64: str, private_key_pem: str) -> str:
        """
        Hybrid Decryption:
        1. Decrypts AES key with Recipient's RSA Private Key.
        2. Decrypts ciphertext with AES-256-GCM.
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None
        )

        raw_json = base64.b64decode(encrypted_envelope_b64.encode('utf-8')).decode('utf-8')
        envelope = json.loads(raw_json)

        encrypted_aes_key = base64.b64decode(envelope["enc_key"])
        iv = base64.b64decode(envelope["iv"])
        ciphertext_and_tag = base64.b64decode(envelope["payload"])

        # Decrypt AES key
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt payload
        aesgcm = AESGCM(aes_key)
        decrypted_bytes = aesgcm.decrypt(iv, ciphertext_and_tag, None)
        return decrypted_bytes.decode('utf-8')

    @staticmethod
    def sign_message(message: str, private_key_pem: str) -> str:
        """Sign a message using RSA-PSS with SHA-256."""
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None
        )
        signature = private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify_signature(message: str, signature_b64: str, public_key_pem: str) -> dict:
        """Verify message signature with RSA-PSS SHA-256."""
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
            signature = base64.b64decode(signature_b64.encode('utf-8'))

            public_key.verify(
                signature,
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return {
                "valid": True,
                "message": "Signature is VALID. The message authenticity and integrity are verified."
            }
        except Exception as e:
            return {
                "valid": False,
                "message": f"Signature verification FAILED: Email was tampered with or key is mismatched ({str(e)})."
            }
