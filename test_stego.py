"""
test_stego.py
=============
Automated test suite for "Secure Image Steganography with AES Encryption".

Tests:
1. PBKDF2 Key Derivation determinism and salt uniqueness.
2. AES-256-GCM Encryption and Decryption roundtrip.
3. Decryption failure on incorrect password (InvalidTag).
4. Decryption failure on tampered/corrupted ciphertext.
5. Image capacity calculation and capacity overflow detection.
6. End-to-end Steganography Encode & Decode roundtrip on RGB images.
7. Steganography decoding with incorrect password.
8. Steganography detection failure on clean/unencoded images.
9. Handling of Unicode, emojis, newlines, and special characters.
10. Carrier image format handling (JPEG converted to RGB then saved as PNG).
"""

import io
import unittest
from PIL import Image

from crypto_utils import (
    derive_key,
    encrypt_message,
    decrypt_message,
    CryptoError,
    DecryptionError,
)
from stego_utils import (
    get_image_capacity,
    format_bytes,
    estimate_payload_size,
    encode_message_into_image,
    decode_message_from_image,
    SteganographyError,
    CapacityExceededError,
)


class TestCryptoUtils(unittest.TestCase):
    """Unit tests for PBKDF2 key derivation and AES-256-GCM encryption."""

    def test_key_derivation_deterministic(self):
        """Same password and salt must always produce identical 32-byte key."""
        salt = b"\x01" * 16
        key1 = derive_key("MyPassword123", salt)
        key2 = derive_key("MyPassword123", salt)
        self.assertEqual(len(key1), 32)
        self.assertEqual(key1, key2)

    def test_key_derivation_salt_diversity(self):
        """Different salts with the same password must produce different keys."""
        salt1 = b"\x01" * 16
        salt2 = b"\x02" * 16
        key1 = derive_key("MyPassword123", salt1)
        key2 = derive_key("MyPassword123", salt2)
        self.assertNotEqual(key1, key2)

    def test_crypto_roundtrip(self):
        """Plaintext encrypted with password must decrypt back identically."""
        message = "This is a confidential message for Alice from Bob."
        password = "CorrectHorseBatteryStaple"

        salt, nonce, ciphertext = encrypt_message(message, password)
        self.assertEqual(len(salt), 16)
        self.assertEqual(len(nonce), 12)
        self.assertGreater(len(ciphertext), len(message))

        decrypted = decrypt_message(salt, nonce, ciphertext, password)
        self.assertEqual(decrypted, message)

    def test_crypto_wrong_password(self):
        """Decrypting with wrong password must raise DecryptionError."""
        message = "Secret plans"
        salt, nonce, ciphertext = encrypt_message(message, "RightPassword")

        with self.assertRaises(DecryptionError):
            decrypt_message(salt, nonce, ciphertext, "WrongPassword")

    def test_crypto_tampered_ciphertext(self):
        """Tampering with any ciphertext bit must trigger GCM tag verification failure."""
        message = "Integrity critical data"
        password = "SecurePassword456"
        salt, nonce, ciphertext = encrypt_message(message, password)

        # Flip one byte in the ciphertext
        tampered_bytes = bytearray(ciphertext)
        tampered_bytes[0] ^= 0x01
        tampered_ciphertext = bytes(tampered_bytes)

        with self.assertRaises(DecryptionError):
            decrypt_message(salt, nonce, tampered_ciphertext, password)

    def test_crypto_empty_inputs(self):
        """Empty plaintext or empty password must raise CryptoError."""
        with self.assertRaises(CryptoError):
            encrypt_message("", "password")
        with self.assertRaises(CryptoError):
            encrypt_message("message", "")


class TestStegoUtils(unittest.TestCase):
    """Unit tests for LSB Steganography encoding, decoding, and capacity logic."""

    def setUp(self):
        # Create standard test images
        self.small_img = Image.new("RGB", (60, 60), color=(100, 150, 200))
        self.med_img = Image.new("RGB", (200, 200), color=(50, 75, 100))

    def test_capacity_calculation(self):
        """Capacity formula: (w * h * 3) // 8 bytes."""
        # 60 * 60 = 3600 pixels * 3 channels = 10,800 bits // 8 = 1350 bytes
        self.assertEqual(get_image_capacity(self.small_img), 1350)
        # 200 * 200 = 40,000 pixels * 3 channels = 120,000 bits // 8 = 15,000 bytes
        self.assertEqual(get_image_capacity(self.med_img), 15000)

    def test_capacity_formatting(self):
        """Verify format_bytes produces expected human-readable strings."""
        self.assertEqual(format_bytes(500), "500 B")
        self.assertEqual(format_bytes(1024), "1.00 KB")
        self.assertEqual(format_bytes(1048576), "1.00 MB")

    def test_capacity_exceeded_error(self):
        """Embedding a message larger than image capacity must raise CapacityExceededError."""
        # A tiny 10x10 image has (100 * 3) // 8 = 37 bytes capacity
        tiny_img = Image.new("RGB", (10, 10), color=(255, 255, 255))
        long_message = "A" * 200  # Requires >250 bytes with overhead

        with self.assertRaises(CapacityExceededError):
            encode_message_into_image(tiny_img, long_message, "pass123")

    def test_stego_roundtrip(self):
        """Full encode and decode roundtrip on synthetic image."""
        secret = "Top-secret coordinates: 37.7749 N, 122.4194 W."
        password = "AlphaBravoCharlie123!"

        encoded_img, stats = encode_message_into_image(self.med_img, secret, password)
        self.assertIn("total_capacity", stats)
        self.assertIn("payload_size", stats)
        self.assertGreater(stats["payload_size"], 0)
        self.assertLessEqual(stats["payload_size"], stats["total_capacity"])

        # Decode using the correct password
        extracted = decode_message_from_image(encoded_img, password)
        self.assertEqual(extracted, secret)

    def test_stego_wrong_password_error(self):
        """Extracting with wrong password from encoded image raises DecryptionError."""
        secret = "Classified dossier."
        encoded_img, _ = encode_message_into_image(self.med_img, secret, "ValidPass")

        with self.assertRaises(DecryptionError):
            decode_message_from_image(encoded_img, "IncorrectPass")

    def test_stego_unencoded_image_error(self):
        """Decoding an unencoded image must raise SteganographyError (signature missing)."""
        clean_img = Image.new("RGB", (150, 150), color=(200, 200, 200))
        with self.assertRaises(SteganographyError):
            decode_message_from_image(clean_img, "AnyPassword")

    def test_stego_unicode_and_emojis(self):
        """Verify steganography properly preserves Unicode, accents, and emojis."""
        unicode_message = (
            "🔒 Secret Transmission 🚀\n"
            "Languages: Español (año), 日本語 (こんにちは), Русский (Привет), العربية (مرحبا)\n"
            "Symbols: © ® ™ § ¶ † ‡ • ♠ ♣ ♥ ♦\n"
            "Multiline\nand special characters: !@#$%^&*()_+-=[]{}|;':,.<>?"
        )
        password = "UnicodeP@ssw0rd🌟"

        encoded_img, _ = encode_message_into_image(self.med_img, unicode_message, password)
        extracted = decode_message_from_image(encoded_img, password)
        self.assertEqual(extracted, unicode_message)

    def test_jpeg_carrier_to_png_workflow(self):
        """
        Verify that a carrier image originating from JPEG compression
        can be loaded, converted to RGB, encoded, and saved to PNG losslessly.
        """
        # Create a synthetic image and save it as JPEG in memory
        raw_canvas = Image.new("RGB", (120, 120), color=(80, 120, 160))
        jpeg_buffer = io.BytesIO()
        raw_canvas.save(jpeg_buffer, format="JPEG", quality=90)
        jpeg_buffer.seek(0)

        # Open the JPEG buffer (simulating user uploading a .jpg file)
        uploaded_jpeg = Image.open(jpeg_buffer)

        secret = "Extracted from an image that started as a JPEG!"
        password = "JpegPassword123"

        # Encode (internal logic converts to RGB and embeds)
        encoded_img, _ = encode_message_into_image(uploaded_jpeg, secret, password)

        # Save as PNG buffer (simulating saving as PNG)
        png_buffer = io.BytesIO()
        encoded_img.save(png_buffer, format="PNG")
        png_buffer.seek(0)

        # Open PNG and decode
        loaded_png = Image.open(png_buffer)
        decoded = decode_message_from_image(loaded_png, password)
        self.assertEqual(decoded, secret)


if __name__ == "__main__":
    unittest.main()
