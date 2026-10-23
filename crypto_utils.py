"""
crypto_utils.py
================
Cryptographic utilities for "Secure Image Steganography with AES Encryption".

Educational Concepts Covered:
1. PBKDF2-HMAC-SHA256 Key Derivation:
   Passwords entered by humans typically have low entropy and variable length.
   A cryptographic Key Derivation Function (KDF) like PBKDF2 applies a pseudo-random
   function (HMAC-SHA256) along with a unique salt across thousands of iterations
   (here, 200,000 iterations) to produce a cryptographically secure 256-bit (32-byte) key.
   This drastically slows down brute-force and dictionary attacks.

2. AES-256-GCM (Galois/Counter Mode):
   AES (Advanced Encryption Standard) with a 256-bit key provides military-grade
   confidentiality. GCM mode is an "Authenticated Encryption with Associated Data" (AEAD)
   mode. It not only encrypts the secret message, but also produces a 16-byte authentication
   tag that guarantees the data has not been modified or corrupted. If even a single bit
   is changed (or if the wrong password is supplied), GCM authentication fails immediately.

3. Cryptographic Nonce (Number used Once):
   In GCM mode, every encryption must use a unique 12-byte (96-bit) nonce.
   Reusing a nonce with the same key destroys GCM security. We generate a fresh random
   nonce for each encryption using the operating system's CSPRNG (os.urandom).
"""

import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


# Configuration Constants
PBKDF2_ITERATIONS = 200_000   # 200,000 iterations balances security & responsiveness
SALT_BYTE_LENGTH = 16         # 128-bit random salt
NONCE_BYTE_LENGTH = 12        # 96-bit random nonce standard for AES-GCM
KEY_BYTE_LENGTH = 32          # 256-bit AES key


class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails due to wrong password or corrupted data."""
    pass


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 256-bit AES key from a human password and salt using PBKDF2-HMAC-SHA256.

    Args:
        password: The user's secret password string.
        salt: A 16-byte random salt unique to this encryption operation.

    Returns:
        32 bytes (256 bits) representing the derived AES key.

    Raises:
        CryptoError: If the password is empty or invalid.
    """
    if not password:
        raise CryptoError("Password cannot be empty.")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_BYTE_LENGTH:
        raise CryptoError(f"Salt must be exactly {SALT_BYTE_LENGTH} bytes.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_BYTE_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_message(plaintext: str, password: str) -> tuple[bytes, bytes, bytes]:
    """
    Encrypts a plaintext string using AES-256-GCM with a password-derived key.

    Process:
      1. Generate a random 16-byte salt (os.urandom).
      2. Derive a 256-bit key from the password and salt.
      3. Generate a random 12-byte nonce (os.urandom).
      4. Encrypt the plaintext bytes with AESGCM.
         (The resulting ciphertext includes the 16-byte authentication tag).

    Args:
        plaintext: The secret text message to be hidden.
        password: The secret password chosen by the user.

    Returns:
        tuple of (salt: bytes, nonce: bytes, ciphertext: bytes)

    Raises:
        CryptoError: If plaintext or password is empty.
    """
    if plaintext is None or len(plaintext) == 0:
        raise CryptoError("Secret message cannot be empty.")
    if not password:
        raise CryptoError("Password cannot be empty.")

    # 1. Generate fresh salt and nonce
    salt = os.urandom(SALT_BYTE_LENGTH)
    nonce = os.urandom(NONCE_BYTE_LENGTH)

    # 2. Derive 256-bit key
    key = derive_key(password, salt)

    # 3. Encrypt plaintext (UTF-8 encoded)
    aesgcm = AESGCM(key)
    plaintext_bytes = plaintext.encode("utf-8")
    
    # AESGCM.encrypt appends a 16-byte tag to the ciphertext
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)

    return salt, nonce, ciphertext


def decrypt_message(salt: bytes, nonce: bytes, ciphertext: bytes, password: str) -> str:
    """
    Decrypts an AES-256-GCM ciphertext using a password-derived key.

    Process:
      1. Re-derive the 256-bit key from the password and the provided salt.
      2. Decrypt the ciphertext with AESGCM using the provided nonce.
         (AESGCM automatically verifies the 16-byte authentication tag).
      3. Decode the decrypted bytes back into a UTF-8 string.

    Args:
        salt: The 16-byte salt extracted from the image.
        nonce: The 12-byte nonce extracted from the image.
        ciphertext: The encrypted payload (including the GCM tag).
        password: The password supplied by the user attempting to decrypt.

    Returns:
        The decrypted plaintext string.

    Raises:
        DecryptionError: If the password is incorrect or the ciphertext was tampered with.
        CryptoError: If inputs are invalid or text encoding fails.
    """
    if not password:
        raise CryptoError("Password cannot be empty.")
    if not salt or len(salt) != SALT_BYTE_LENGTH:
        raise CryptoError(f"Invalid salt: Expected {SALT_BYTE_LENGTH} bytes.")
    if not nonce or len(nonce) != NONCE_BYTE_LENGTH:
        raise CryptoError(f"Invalid nonce: Expected {NONCE_BYTE_LENGTH} bytes.")
    if not ciphertext or len(ciphertext) < 16:
        raise DecryptionError("Ciphertext is too short to contain an authenticated payload.")

    # 1. Derive key with the same password and extracted salt
    key = derive_key(password, salt)

    # 2. Decrypt with AESGCM
    aesgcm = AESGCM(key)
    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag:
        # InvalidTag means either the password produced the wrong key, or the ciphertext/tag was modified
        raise DecryptionError(
            "Decryption failed: Incorrect password or corrupted/tampered data."
        )
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {e}")

    # 3. Decode UTF-8 plaintext
    try:
        return decrypted_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise DecryptionError(
            "Authentication passed, but message could not be decoded as valid UTF-8 text."
        )
