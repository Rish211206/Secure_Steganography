# Secure Image Steganography with AES-256 Encryption

An educational Python desktop application that demonstrates how to combine **authenticated cryptography** with **least significant bit (LSB) steganography** to secretly and securely hide confidential messages inside digital images.

Built with **Python 3**, **Tkinter / ttk**, **Pillow (PIL)**, and the **cryptography** library.

---

## 📑 Table of Contents
1. [Core Concepts & Theory](#-core-concepts--theory)
   - [Cryptography vs. Steganography](#1-cryptography-vs-steganography)
   - [Key Derivation: PBKDF2-HMAC-SHA256](#2-key-derivation-pbkdf2-hmac-sha256)
   - [Authenticated Encryption: AES-256-GCM](#3-authenticated-encryption-aes-256-gcm)
   - [Least Significant Bit (LSB) Steganography](#4-least-significant-bit-lsb-steganography)
   - [Why PNG is Essential (and why JPEG breaks it)](#5-why-png-is-essential-and-why-jpeg-breaks-it)
2. [Project Structure](#-project-structure)
3. [Installation & Requirements](#-installation--requirements)
4. [Running the Application](#-running-the-application)
   - [Launching the Desktop GUI](#launching-the-desktop-gui)
   - [Running Automated Unit Tests](#running-automated-unit-tests)
   - [Generating Sample Images](#generating-sample-images)
5. [User Guide](#-user-guide)
   - [Encoding Workflow](#encoding-workflow-hiding-a-message)
   - [Decoding Workflow](#decoding-workflow-revealing-a-message)
6. [Binary Packet Framing Format](#-binary-packet-framing-format)
7. [Error Handling & Edge Cases](#-error-handling--edge-cases)
8. [Security & Educational Disclaimer](#-security--educational-disclaimer)

---

## 🧠 Core Concepts & Theory

### 1. Cryptography vs. Steganography
- **Cryptography** scrambles the *meaning* of a message using mathematical algorithms. Anyone inspecting the data sees random-looking ciphertext and cannot read it without the secret key. However, the presence of encrypted data can attract unwanted attention.
- **Steganography** conceals the *very existence* of a message by embedding it into an innocent-looking carrier medium (such as a digital photograph). An observer cannot tell by looking that anything is hidden.
- **Combining Both (Defense-in-Depth):** This application encrypts the secret message first using AES-256-GCM and then hides the resulting ciphertext inside the pixel channels of an image. If someone discovers that an image has hidden data, they still cannot decrypt it without the password.

### 2. Key Derivation: PBKDF2-HMAC-SHA256
Human-chosen passwords vary in length and often lack sufficient entropy. Cryptographic algorithms like AES require uniform, high-entropy 256-bit (32-byte) keys.
- **PBKDF2 (Password-Based Key Derivation Function 2)** applies a pseudo-random function (`HMAC-SHA256`) along with a cryptographically secure random 16-byte salt across **200,000 iterations**.
- This deliberate computational work drastically slows down brute-force and pre-computed rainbow table attacks.
- Each encryption generates a fresh, unique salt, ensuring that the same password produces completely different AES keys each time.

### 3. Authenticated Encryption: AES-256-GCM
- **AES (Advanced Encryption Standard)** with a 256-bit key provides robust symmetric encryption.
- **GCM (Galois/Counter Mode)** is an *Authenticated Encryption with Associated Data (AEAD)* mode.
- In addition to encrypting the plaintext, GCM computes a **16-byte authentication tag**.
- When decrypting, AES-GCM recalculates this tag. If the wrong password was used, or if even a single bit of the image or ciphertext was modified or corrupted, tag verification fails immediately (`InvalidTag`), preventing malicious tampering and silent corruption.
- Every encryption operation generates a unique random **12-byte (96-bit) Nonce** (`os.urandom(12)`) to ensure nonce reuse never occurs.

### 4. Least Significant Bit (LSB) Steganography
- A standard digital RGB image represents every pixel with 3 color channels: **Red**, **Green**, and **Blue**.
- Each channel byte holds an 8-bit integer between 0 and 255 (`00000000` to `11111111`).
- The **Least Significant Bit (LSB)** is bit 0 (the rightmost bit, value 1).
- Modifying the LSB changes the color channel brightness by at most $\pm 1$ unit out of 255 (e.g., changing Red from 180 to 181). This alteration is completely imperceptible to the human eye.
- **Capacity calculation:**
  $$\text{Capacity in Bits} = \text{Width} \times \text{Height} \times 3$$
  $$\text{Capacity in Bytes} = \lfloor \frac{\text{Width} \times \text{Height} \times 3}{8} \rfloor$$
  For example, a modest $500 \times 400$ image provides:
  $$\frac{500 \times 400 \times 3}{8} = 75,000 \text{ bytes (75 KB)}$$
  which can store thousands of words of encrypted text.

### 5. Why PNG is Essential (and why JPEG breaks it)
- **PNG (Portable Network Graphics):** Uses **lossless** Deflate compression. Every single pixel channel byte is saved and restored with 100% mathematical fidelity. The LSBs remain completely intact.
- **JPEG (Joint Photographic Experts Group):** Uses **lossy** compression based on Discrete Cosine Transforms (DCT) and quantization tables. JPEG deliberately discards high-frequency pixel variations to reduce file size. This alters pixel values by $\pm 1$, $\pm 2$, or more, which completely destroys the embedded LSB data.
- **Rule:** You can upload JPG or PNG files as carrier images, but the encoded output must **always be saved as PNG**.

---

## 📂 Project Structure

```text
secure_steganography_app/
├── crypto_utils.py          # PBKDF2-HMAC-SHA256 key derivation & AES-256-GCM encryption
├── stego_utils.py           # LSB embedding, extraction, framing header, & capacity math
├── gui.py                   # Tkinter/ttk desktop GUI (Encode/Decode tabs, meter, preview)
├── main.py                  # Entrypoint script (launches GUI or test suite)
├── test_stego.py            # Automated test suite (14 unit tests)
├── create_sample_images.py  # Utility script to generate sample PNG & JPG test carriers
├── requirements.txt         # Pinned Python package dependencies
└── README.md                # Detailed project documentation and educational guide
```

### Explanation of Files
- **`crypto_utils.py`**: Contains `derive_key()`, `encrypt_message()`, and `decrypt_message()`. Handles all cryptographic primitives and defines `DecryptionError` for clear reporting of invalid passwords or tampered data.
- **`stego_utils.py`**: Converts images to RGB, calculates capacity, and efficiently replaces channel LSBs using `bytearray` operations. Houses `encode_message_into_image()` and `decode_message_from_image()`.
- **`gui.py`**: Implements the modern `SteganographyApp` window using Tkinter and `ttk.Notebook`. Features responsive layout, image thumbnails, live capacity meter, password visibility toggles, clipboard support, and friendly error dialogs.
- **`main.py`**: Clean application launcher supporting normal GUI execution or `--test` flag for headless test verification.
- **`test_stego.py`**: Unittest suite asserting cryptographic correctness, wrong password handling, tampered ciphertext detection, capacity bounds, round-trip encoding/decoding, and Unicode support.

---

## ⚙️ Installation & Requirements

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13 installed on your system.
- Tkinter (included by default with official Python installers on Windows and macOS; on Ubuntu/Debian Linux, install via `sudo apt-get install python3-tk`).

### Step-by-Step Setup

1. **Open your terminal or PowerShell** and navigate to the project directory:
   ```bash
   cd C:\Users\HP\.gemini\antigravity\scratch\secure_steganography_app
   ```

2. **Create a Python virtual environment**:
   ```bash
   python -m venv .venv
   ```

3. **Activate the virtual environment**:
   - On Windows (PowerShell):
     ```powershell
     .\.venv\Scripts\Activate.ps1
     ```
   - On Windows (Command Prompt):
     ```cmd
     .venv\Scripts\activate.bat
     ```
   - On macOS / Linux:
     ```bash
     source .venv/bin/activate
     ```

4. **Install the required dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   *(Or install directly: `pip install cryptography pillow`)*

---

## 🚀 Running the Application

### Launching the Desktop GUI
With your virtual environment activated, run:
```bash
python main.py
```
*(On Windows PowerShell without activating, you can also run directly:)*
```powershell
& ".\.venv\Scripts\python.exe" main.py
```

### Running Automated Unit Tests
To verify all cryptographic routines, steganography bit manipulation, and edge cases:
```bash
python main.py --test
```
or:
```bash
python -m unittest test_stego.py
```
**Expected Test Output:**
```text
test_crypto_empty_inputs (test_stego.TestCryptoUtils.test_crypto_empty_inputs) ... ok
test_crypto_roundtrip (test_stego.TestCryptoUtils.test_crypto_roundtrip) ... ok
test_crypto_tampered_ciphertext (test_stego.TestCryptoUtils.test_crypto_tampered_ciphertext) ... ok
test_crypto_wrong_password (test_stego.TestCryptoUtils.test_crypto_wrong_password) ... ok
test_key_derivation_deterministic (test_stego.TestCryptoUtils.test_key_derivation_deterministic) ... ok
test_key_derivation_salt_diversity (test_stego.TestCryptoUtils.test_key_derivation_salt_diversity) ... ok
test_capacity_calculation (test_stego.TestStegoUtils.test_capacity_calculation) ... ok
test_capacity_exceeded_error (test_stego.TestStegoUtils.test_capacity_exceeded_error) ... ok
test_capacity_formatting (test_stego.TestStegoUtils.test_capacity_formatting) ... ok
test_jpeg_carrier_to_png_workflow (test_stego.TestStegoUtils.test_jpeg_carrier_to_png_workflow) ... ok
test_stego_roundtrip (test_stego.TestStegoUtils.test_stego_roundtrip) ... ok
test_stego_unencoded_image_error (test_stego.TestStegoUtils.test_stego_unencoded_image_error) ... ok
test_stego_unicode_and_emojis (test_stego.TestStegoUtils.test_stego_unicode_and_emojis) ... ok
test_stego_wrong_password_error (test_stego.TestStegoUtils.test_stego_wrong_password_error) ... ok

----------------------------------------------------------------------
Ran 14 tests in 0.701s

OK
```

### Generating Sample Images
A helper script is included to generate ready-to-use sample carrier images:
```bash
python create_sample_images.py
```
This generates:
- `sample_carrier.png`: A $500 \times 400$ PNG image (75 KB capacity).
- `sample_carrier.jpg`: A $500 \times 400$ JPEG image to demonstrate converting JPEG carriers into PNG stego files.

---

## 🖥️ User Guide

### Encoding Workflow (Hiding a Message)
1. Select the **Encode (Hide & Encrypt)** tab.
2. Click **📁 Browse Carrier Image...** and select any PNG or JPG photo.
   - The app displays image dimensions, total pixels, and maximum byte capacity.
   - A thumbnail preview will render in the top right.
3. Type or paste your secret message in the **Secret Message** box.
   - The **Capacity Meter** updates in real-time, showing required bytes and percentage of carrier capacity used.
4. Enter an encryption password in **Secret Password** and re-enter it in **Confirm Password**.
5. Click **🔒 Encrypt & Save Encoded Image as PNG**.
6. Choose a destination path. The app will encrypt the message with AES-256-GCM, embed the ciphertext into pixel LSBs, and save the resulting image losslessly as `.png`.

### Decoding Workflow (Revealing a Message)
1. Select the **Decode (Extract & Decrypt)** tab.
2. Click **📁 Browse Encoded Image...** and select the encoded `.png` file.
3. Enter the secret password used during encoding.
4. Click **🔓 Extract & Decrypt Secret Message**.
5. The extracted plaintext message will appear in the decrypted text area.
6. Click **📋 Copy to Clipboard** to copy the revealed message.

---

## 📦 Binary Packet Framing Format

The embedded bitstream uses the following binary framing structure:

| Field | Size | Description |
| :--- | :--- | :--- |
| **Magic Signature** | 4 bytes | Fixed ASCII bytes `b'AEST'` to identify encoded images |
| **Protocol Version**| 1 byte  | Protocol version (`0x01`) |
| **Payload Length**  | 4 bytes | Big-endian 32-bit unsigned integer ($N$) |
| **PBKDF2 Salt**     | 16 bytes| Cryptographically random salt for key derivation |
| **AES-GCM Nonce**   | 12 bytes| Unique 96-bit nonce for AES-GCM |
| **Ciphertext + Tag**| $N - 28$ bytes | AES-256 ciphertext + 16-byte GCM authentication tag |

**Total Overhead:** 53 bytes.

### Why this design is robust:
- **Instant Non-Payload Rejection:** If an unencoded image is selected, the decoder checks the first 4 bytes (`b'AEST'`). If missing, it immediately aborts with a friendly error without attempting costly decryption.
- **Tamper Resistance:** If an attacker modifies even a single pixel bit within the payload, AES-GCM tag verification fails upon decryption.

---

## 🛡️ Error Handling & Edge Cases

The application handles common pitfalls with user-friendly dialogs:
1. **Wrong Password on Decryption:**
   - Displays: *"Decryption failed: Incorrect password or corrupted/tampered data."*
2. **Unencoded or Corrupted Image:**
   - Displays: *"No hidden steganographic payload detected in this image."*
   - Explains that the image may not be encoded or was compressed with JPEG.
3. **Insufficient Image Capacity:**
   - The UI warns you before saving if payload exceeds capacity.
   - Displays: *"Image capacity exceeded! Required: X bytes, Available: Y bytes. Please use a larger image or shorten the message."*
4. **Password Mismatch:**
   - Alerts the user if the confirmation password does not match.
5. **Unicode & Emojis:**
   - Full UTF-8 encoding ensures multi-language text, accents, and emojis (e.g. `🔒 🚀`) are safely preserved.

---

## ⚠️ Security & Educational Disclaimer

This software was developed as an **educational project** to demonstrate the mechanics of authenticated symmetric encryption and digital image steganography.
- **Statistical Steganalysis:** Simple LSB steganography alters the least significant bit in a sequential pattern starting at pixel $(0,0)$. Advanced statistical tools (such as chi-square steganalysis or sample pair analysis) can detect unusual bit distributions in the LSB plane of an image.
- **Lossy Compression Warning:** Never send encoded steganographic images through social media platforms (e.g., WhatsApp, Discord, Twitter/X) that re-compress or re-encode images as JPEG or WebP, as this will destroy the LSB payload. Transmit encoded images as lossless PNG files (or as uncompressed file attachments).
