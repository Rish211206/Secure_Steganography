"""
stego_utils.py
==============
Least Significant Bit (LSB) Steganography implementation for RGB images.

Educational Concepts Covered:
1. What is Steganography?
   While Cryptography scrambles a message so unauthorized parties cannot read it,
   Steganography hides the very existence of the message inside innocuous carrier
   data (like a digital photograph). Combining both provides "defense-in-depth":
   an observer does not suspect a secret message is present, and even if they
   detect hidden data, they cannot decrypt it without the AES-256 key.

2. How Least Significant Bit (LSB) Steganography Works:
   - Digital RGB images represent every pixel with 3 color channels: Red, Green, and Blue.
   - Each channel is an 8-bit integer ranging from 0 to 255 (binary: 00000000 to 11111111).
   - The Least Significant Bit (LSB) is bit 0 (the rightmost bit, value 1).
   - Changing the LSB alters the channel's brightness value by at most ±1 out of 255.
     For example, RGB(180, 92, 240) -> RGB(181, 92, 241).
   - This tiny difference is completely imperceptible to the human eye!
   - 1 pixel = 3 channels = 3 bits of secret data.
   - 8 channels = 8 bits = 1 full byte of secret data.

3. Why PNG is required (and why JPEG breaks steganography):
   - PNG uses lossless Deflate compression. Every single pixel value and LSB is
     preserved exactly as encoded.
   - JPEG uses lossy compression (Discrete Cosine Transform and quantization).
     Saving an image as JPEG slightly alters pixel values to reduce file size,
     which destroys the least significant bits and corrupts the hidden ciphertext.
   - Therefore, while any image (PNG, JPG, BMP) can be used as the input carrier,
     the encoded output must always be saved as a PNG file.

4. Binary Packet Structure Embedded in Image:
   [ 4 bytes: Magic Signature b'AEST' ]
   [ 1 byte : Protocol Version (0x01) ]
   [ 4 bytes: Payload Length (big-endian uint32) ]
   [ Payload:
       - 16 bytes: PBKDF2 Salt
       - 12 bytes: AES-GCM Nonce
       - N  bytes: AES-GCM Ciphertext (includes 16-byte GCM Auth Tag)
   ]
"""

import struct
from PIL import Image
from crypto_utils import encrypt_message, decrypt_message, CryptoError, DecryptionError


# Framing Constants
MAGIC_HEADER = b"AEST"          # 4-byte signature to identify valid encoded images
PROTOCOL_VERSION = 1            # 1-byte protocol version
HEADER_FIXED_SIZE = 9           # 4 (magic) + 1 (version) + 4 (length) = 9 bytes
MIN_PAYLOAD_SIZE = 16 + 12 + 16  # 16 (salt) + 12 (nonce) + 16 (min GCM tag) = 44 bytes


class SteganographyError(Exception):
    """Base exception for steganography errors."""
    pass


class CapacityExceededError(SteganographyError):
    """Raised when the message payload is too large to fit in the image."""
    pass


def get_image_capacity(image: Image.Image) -> int:
    """
    Calculates the maximum payload capacity of an image in bytes.

    Each pixel has 3 color channels (R, G, B), and each channel stores 1 bit.
    Total capacity = (width * height * 3) // 8 bytes.

    Args:
        image: A PIL Image instance.

    Returns:
        Maximum number of bytes that can be safely embedded.
    """
    width, height = image.size
    total_bits = width * height * 3
    return total_bits // 8


def format_bytes(size_in_bytes: int) -> str:
    """
    Returns a human-readable string representation of a byte size.
    Example: 1024 -> '1.00 KB', 1048576 -> '1.00 MB'.
    """
    if size_in_bytes < 1024:
        return f"{size_in_bytes} B"
    elif size_in_bytes < 1024 * 1024:
        return f"{size_in_bytes / 1024:.2f} KB"
    else:
        return f"{size_in_bytes / (1024 * 1024):.2f} MB"


def estimate_payload_size(message_text: str) -> int:
    """
    Estimates the total binary packet size needed to store the encrypted message.

    Packet layout:
      4 bytes: Magic 'AEST'
      1 byte : Version
      4 bytes: Length
      16 bytes: Salt
      12 bytes: Nonce
      len(message.encode('utf-8')) + 16 bytes: AES-GCM Ciphertext + Tag
    Total overhead = 53 bytes.
    """
    message_bytes_len = len(message_text.encode("utf-8")) if message_text else 0
    overhead = HEADER_FIXED_SIZE + 16 + 12 + 16  # 53 bytes
    return overhead + message_bytes_len


def _bytes_to_bits(data: bytes) -> list[int]:
    """Converts a bytes sequence into a flat list of bits (0 or 1, MSB to LSB)."""
    bits = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    """Reconstructs a bytes object from a list of bit integers (0 or 1)."""
    byte_list = []
    for i in range(0, len(bits), 8):
        byte_val = 0
        for bit in bits[i:i + 8]:
            byte_val = (byte_val << 1) | bit
        byte_list.append(byte_val)
    return bytes(byte_list)


def encode_message_into_image(
    carrier_image: Image.Image,
    secret_message: str,
    password: str
) -> tuple[Image.Image, dict]:
    """
    Encrypts a secret message with AES-256-GCM and embeds it into the carrier image
    using Least Significant Bit (LSB) steganography.

    Args:
        carrier_image: The PIL Image to embed the data into (PNG or JPG).
        secret_message: The secret plaintext string to hide.
        password: The encryption password.

    Returns:
        tuple of (encoded_image: Image.Image, stats: dict)
        stats contains:
          - 'total_capacity': total bytes image can hold
          - 'payload_size': total bytes embedded
          - 'used_percentage': percent of capacity used
          - 'image_dimensions': (width, height)

    Raises:
        CryptoError: If message or password validation fails.
        CapacityExceededError: If the encrypted payload exceeds image capacity.
        SteganographyError: If an error occurs during encoding.
    """
    if not secret_message:
        raise CryptoError("Secret message cannot be empty.")
    if not password:
        raise CryptoError("Password cannot be empty.")

    # 1. Convert image to RGB mode (strips alpha/palette while keeping true colors)
    img_rgb = carrier_image.convert("RGB")
    width, height = img_rgb.size
    max_capacity = get_image_capacity(img_rgb)

    # 2. Encrypt the secret message with AES-256-GCM
    salt, nonce, ciphertext = encrypt_message(secret_message, password)

    # 3. Assemble binary payload:
    #    [Salt (16)] + [Nonce (12)] + [Ciphertext + Tag (N)]
    payload = salt + nonce + ciphertext
    payload_len = len(payload)

    # 4. Assemble the full packet with Header:
    #    [Magic (4)] + [Version (1)] + [Payload Length (4)] + [Payload (payload_len)]
    header = MAGIC_HEADER + struct.pack(">B", PROTOCOL_VERSION) + struct.pack(">I", payload_len)
    full_packet = header + payload
    total_packet_bytes = len(full_packet)

    # 5. Check image capacity
    if total_packet_bytes > max_capacity:
        raise CapacityExceededError(
            f"Image capacity exceeded!\n\n"
            f"Required: {format_bytes(total_packet_bytes)} ({total_packet_bytes} bytes)\n"
            f"Available: {format_bytes(max_capacity)} ({max_capacity} bytes)\n\n"
            f"Please use a larger image or shorten the secret message."
        )

    # 6. Convert full packet into a bitstream
    packet_bits = _bytes_to_bits(full_packet)
    total_bits = len(packet_bits)

    # 7. Embed bits into pixel channel bytes using bytearray
    #    Each channel byte's LSB is replaced: (channel & 0xFE) | bit
    raw_channels = bytearray(img_rgb.tobytes())
    for bit_idx in range(total_bits):
        raw_channels[bit_idx] = (raw_channels[bit_idx] & 0xFE) | packet_bits[bit_idx]

    # 8. Reconstruct new PIL Image from the modified channel bytes
    encoded_image = Image.frombytes("RGB", (width, height), bytes(raw_channels))

    stats = {
        "total_capacity": max_capacity,
        "payload_size": total_packet_bytes,
        "used_percentage": (total_packet_bytes / max_capacity) * 100.0,
        "image_dimensions": (width, height),
    }

    return encoded_image, stats


def decode_message_from_image(encoded_image: Image.Image, password: str) -> str:
    """
    Extracts and decrypts a hidden message from an encoded image.

    Args:
        encoded_image: The PIL Image containing the hidden message.
        password: The password to decrypt the extracted ciphertext.

    Returns:
        The decrypted plaintext message string.

    Raises:
        SteganographyError: If no steganographic payload is detected or header is invalid.
        DecryptionError: If the password is wrong or data is corrupted.
        CryptoError: For validation failures.
    """
    if not password:
        raise CryptoError("Password cannot be empty.")

    # 1. Convert to RGB mode
    img_rgb = encoded_image.convert("RGB")
    width, height = img_rgb.size
    max_capacity = get_image_capacity(img_rgb)

    # 2. Check if the image is at least large enough to hold the fixed header
    if max_capacity < HEADER_FIXED_SIZE:
        raise SteganographyError(
            "Image is too small to contain a valid steganographic payload."
        )

    raw_channels = bytearray(img_rgb.tobytes())

    # 3. Read the 9-byte header (9 * 8 = 72 bits)
    header_bits = [raw_channels[i] & 1 for i in range(HEADER_FIXED_SIZE * 8)]
    header_bytes = _bits_to_bytes(header_bits)

    magic = header_bytes[0:4]
    version = header_bytes[4]
    payload_len = struct.unpack(">I", header_bytes[5:9])[0]

    # 4. Verify magic signature
    if magic != MAGIC_HEADER:
        raise SteganographyError(
            "No hidden steganographic payload detected in this image.\n\n"
            "Possible causes:\n"
            "• This image was not encoded with this application.\n"
            "• The image was saved or modified as a lossy JPEG, which destroyed the hidden bits.\n"
            "• The image was cropped, resized, or re-compressed."
        )

    # 5. Verify protocol version
    if version != PROTOCOL_VERSION:
        raise SteganographyError(
            f"Unsupported steganography payload version: {version}. "
            f"Expected version {PROTOCOL_VERSION}."
        )

    # 6. Validate payload length
    if payload_len < MIN_PAYLOAD_SIZE:
        raise SteganographyError(
            f"Corrupted steganography header: Payload length ({payload_len} bytes) "
            f"is smaller than the minimum expected size ({MIN_PAYLOAD_SIZE} bytes)."
        )

    total_required_bytes = HEADER_FIXED_SIZE + payload_len
    if total_required_bytes > max_capacity:
        raise SteganographyError(
            f"Corrupted steganography header: Specified payload size "
            f"({format_bytes(total_required_bytes)}) exceeds image capacity "
            f"({format_bytes(max_capacity)})."
        )

    # 7. Extract payload bits
    start_bit = HEADER_FIXED_SIZE * 8
    end_bit = start_bit + (payload_len * 8)
    payload_bits = [raw_channels[i] & 1 for i in range(start_bit, end_bit)]
    payload_bytes = _bits_to_bytes(payload_bits)

    # 8. Unpack payload components
    #    [Salt (16 bytes)] [Nonce (12 bytes)] [Ciphertext + Tag (remaining bytes)]
    salt = payload_bytes[0:16]
    nonce = payload_bytes[16:28]
    ciphertext = payload_bytes[28:]

    # 9. Decrypt using AES-256-GCM
    #    (Raises DecryptionError if password is wrong or ciphertext corrupted)
    decrypted_text = decrypt_message(salt, nonce, ciphertext, password)
    return decrypted_text
