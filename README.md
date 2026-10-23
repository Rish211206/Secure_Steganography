# 🔐 Secure Image Steganography with AES-256 Encryption

A Python desktop application that combines **AES-256 authenticated encryption** with **Least Significant Bit (LSB) image steganography** to securely hide confidential text messages inside digital images.

The application allows users to encrypt secret messages, embed them into images, and retrieve the original messages using the appropriate password. It provides a graphical user interface (GUI) for performing encoding and decoding operations.

## 📌 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [How It Works](#-how-it-works)
- [Technology Stack](#-technology-stack)
- [Project Structure](#-project-structure)
- [Prerequisites](#-prerequisites)
- [Installation and Setup](#-installation-and-setup)
- [Running the Application](#-running-the-application)
- [Usage Guide](#-usage-guide)
- [Running Tests](#-running-tests)
- [Sample Files](#-sample-files)
- [Troubleshooting](#-troubleshooting)
- [Security and Limitations](#-security-and-limitations)
- [Future Enhancements](#-future-enhancements)
- [Author](#-author)

## 📖 Overview

Secure Image Steganography is a cybersecurity project designed to demonstrate how cryptography and steganography can work together to protect confidential information.

**Cryptography** protects the content of a message by converting it into encrypted data, while **steganography** hides that data inside an ordinary image.

Instead of transmitting a visible encrypted message, the application embeds the encrypted payload into an image using the Least Significant Bit (LSB) technique.

The resulting image can be shared as an image file. A recipient with the appropriate password can extract and decrypt the hidden message.

## ✨ Features

- **AES-256 Encryption:** Encrypts secret messages before embedding them in an image.
- **Authenticated Encryption:** Uses AES-GCM to provide confidentiality and integrity verification.
- **Password-Based Key Derivation:** Derives an encryption key from a password.
- **LSB Image Steganography:** Hides encrypted data in the least significant bits of image pixel values.
- **Message Encoding:** Embeds an encrypted message into a selected carrier image.
- **Message Extraction:** Retrieves the hidden encrypted payload from an encoded image.
- **Message Decryption:** Decrypts the extracted payload using the correct password.
- **Graphical User Interface:** Provides an interface for performing encoding and decoding operations.
- **Image-Based Data Hiding:** Uses digital images as carriers for secret information.
- **Error Handling:** Helps handle invalid inputs, incorrect passwords, and unsuccessful extraction or decryption operations.

## ⚙️ How It Works

The application combines cryptography and steganography in a sequence of operations.

### 1. Message Encryption

The user enters a secret message and a password. The application derives an encryption key from the password and uses AES-256-GCM to encrypt the message.

The encryption process produces encrypted data and authentication information required for verification and decryption.

### 2. Data Preparation

The encrypted payload is prepared for embedding into the carrier image. The application must preserve the information needed to identify and extract the payload correctly.

### 3. Image Steganography

The encrypted payload is embedded into the least significant bits of the carrier image's pixel values.

LSB steganography modifies pixel values slightly so that data can be stored in the image while generally preserving its visual appearance.

### 4. Encoded Image Generation

The application generates an output image containing the encrypted payload. The encoded image can be saved for later extraction or transfer.

A lossless image format, such as PNG, is recommended to preserve the embedded data.

### 5. Message Extraction

During decoding, the application reads the encoded image and extracts the hidden payload using the corresponding extraction procedure.

### 6. Message Decryption

The extracted payload is decrypted using the correct password-derived key. Authentication verification helps detect an incorrect key or modified encrypted data.

If decryption and authentication succeed, the original secret message is recovered.

**Overall workflow:**

`Secret Message → AES-256-GCM Encryption → LSB Embedding → Encoded Image → Payload Extraction → Decryption → Original Message`

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Python 3 | Core application logic |
| Tkinter / ttk | Desktop graphical user interface |
| Pillow (PIL) | Image loading and processing |
| Python `cryptography` library | Encryption and authenticated decryption |
| LSB Steganography | Hiding encrypted data in image pixels |
| Git and GitHub | Version control and source code hosting |
| pytest / unittest | Testing, depending on the test implementation |

## 📁 Project Structure

```text
secure_steganography_app/
│
├── main.py                  # Main application entry point
├── gui.py                   # Graphical user interface
├── crypto_utils.py          # Cryptographic utility functions
├── stego_utils.py           # Image steganography operations
├── create_sample_images.py  # Sample image generation
├── test_stego.py            # Steganography tests
├── requirements.txt         # Python dependencies
├── README.md                # Project documentation
│
├── sample_carrier.jpg       # Sample carrier image
├── sample_carrier.png       # Sample carrier image
└── sample_encoded.png       # Sample encoded image
```

The `__pycache__` and virtual environment folders are generated locally and do not need to be included in the repository.

## 💻 Prerequisites

Before running the application, ensure that the following are installed:

- **Python 3:** A compatible Python 3 installation.
- **Git:** Required if cloning the project from GitHub.
- **Terminal:** PowerShell or Command Prompt on Windows, or a terminal on Linux/macOS.

Check your installations:

```bash
python --version
git --version
```

On some systems, use `python3` instead of `python`.

## 🚀 Installation and Setup

### Step 1: Clone the Repository

Open a terminal and run:

```bash
git clone https://github.com/Rish211206/Secure_Steganography.git
```

Move into the project directory:

```bash
cd Secure_Steganography
```

If you download the project as a ZIP file instead, extract it and open the extracted project folder in your terminal.

### Step 2: Create a Virtual Environment

A virtual environment keeps the project's Python dependencies separate from other applications.

**Windows — PowerShell or Command Prompt**

```powershell
python -m venv .venv
```

Activate it in PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Or activate it in Command Prompt:

```cmd
.venv\Scripts\activate.bat
```

**Linux/macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Once activated, the environment name may appear at the beginning of your terminal prompt.

### Step 3: Upgrade pip

```bash
python -m pip install --upgrade pip
```

### Step 4: Install Dependencies

Install the required libraries using the provided requirements file:

```bash
python -m pip install -r requirements.txt
```

The application uses Python libraries for image processing, encryption, and its graphical interface.

Tkinter is included with many standard Python installations. On some Linux distributions, it must be installed separately through the operating system's package manager.

### Step 5: Verify the Installation

Check that the principal libraries can be imported:

```bash
python -c "import tkinter, PIL, cryptography; print('Dependencies installed successfully!')"
```

If the command prints the success message, the principal imports are available.

## ▶️ Running the Application

Run the application from the root directory of the project with the virtual environment activated.

```bash
python main.py
```

The graphical interface should open if `main.py` is configured to launch the application.

If the GUI is launched directly from `gui.py` in your version of the project, use:

```bash
python gui.py
```

Use the entry point configured in your project. Do not run both commands simultaneously.

## 🖥️ Usage Guide

### Encoding a Secret Message

1. Launch the application.
2. Select the encoding operation in the interface.
3. Enter the secret message.
4. Enter a strong password.
5. Select a suitable carrier image.
6. Start the encoding operation.
7. Save the generated encoded image to the desired location.
8. Keep the password secure for subsequent decoding.

### Decoding a Secret Message

1. Launch the application.
2. Select the decoding operation.
3. Choose the previously encoded image.
4. Enter the correct password.
5. Start the extraction and decryption process.
6. View the recovered message if authentication and decryption succeed.

The exact button names and input fields depend on the implemented GUI.

## 🧪 Running Tests

The project includes a steganography test file named `test_stego.py`.

Activate the virtual environment and run:

```bash
python -m unittest test_stego.py
```

If the test file uses pytest, install it if necessary:

```bash
python -m pip install pytest
```

Then run:

```bash
python -m pytest -v
```

Use the test runner supported by the actual test file. A successful test run helps verify the implemented operations, but does not by itself establish that the application is secure against every attack.

## 🖼️ Sample Files

The repository includes sample images that can be used to explore the application's workflow.

- `sample_carrier.jpg` — sample carrier image.
- `sample_carrier.png` — sample carrier image.
- `sample_encoded.png` — sample encoded image.

Use the sample files according to the operations supported by the application. An encoded sample will only yield a message if it was generated using the compatible implementation and its corresponding password is available.

## 🐛 Troubleshooting

### 1. `ModuleNotFoundError`

**Cause:** A required Python package is missing or installed in a different environment.

**Solution:**

```bash
python -m pip install -r requirements.txt
```

Ensure that the correct virtual environment is activated.

### 2. Python Command Not Found

**Cause:** Python is not installed correctly or is not available on the system PATH.

**Solution:** Install Python 3 and verify it with:

```bash
python --version
```

On Linux/macOS, try:

```bash
python3 --version
```

### 3. Tkinter Import Error

**Cause:** Tkinter is unavailable in the Python installation.

**Solution:** On Linux, install the appropriate Tkinter package through your distribution's package manager. On Windows, use a Python distribution that includes Tkinter.

### 4. Incorrect Password or Decryption Failure

**Cause:** The supplied password is incorrect, the extracted payload is invalid, or the encrypted data has been modified.

**Solution:** Verify the password and use the original encoded image without altering or recompressing it.

### 5. Hidden Message Cannot Be Extracted

**Cause:** The selected image may not contain a compatible hidden payload, or image processing may have altered the embedded bits.

**Solution:** Select the correct encoded image and avoid lossy image compression, resizing, or editing.

### 6. Image Capacity Error

**Cause:** The encrypted payload may exceed the capacity of the selected carrier image.

**Solution:** Use a larger supported carrier image or a shorter message.

### 7. Application Does Not Open

**Cause:** The wrong entry-point file was run, a dependency is missing, or a runtime error occurred.

**Solution:** Check the terminal output, verify the installation, and run the correct application entry point.

## 🔒 Security and Limitations

This project is intended for educational purposes and demonstrates the integration of authenticated encryption and image steganography.

- **Encryption:** AES-256-GCM protects the confidentiality and integrity of encrypted data when implemented and configured correctly.
- **Password strength:** Weak passwords can make password-derived encryption keys vulnerable to guessing attacks.
- **Steganalysis:** LSB steganography can be detected by statistical analysis and is not guaranteed to conceal the existence of hidden data.
- **Lossy compression:** JPEG recompression, resizing, and image transformations may destroy embedded information.
- **Image capacity:** The amount of data that can be hidden depends on the carrier image and the implementation.
- **Secure handling:** Do not expose passwords or use this educational implementation as a substitute for a professionally audited secure communication system.

## 🔮 Future Enhancements

Possible future improvements include:

- Support for additional carrier image formats.
- Improved payload capacity management.
- Stronger input validation and clearer error messages.
- Automated testing for encryption, extraction, and decryption.
- Improved graphical interface and usability.
- More comprehensive evaluation of image quality and resistance to steganalysis.
- Packaging the application as a standalone executable for easier use on other computers.

## 👩‍💻 Author

**Rishika Singh**

GitHub: [@Rish211206](https://github.com/Rish211206)

## 📄 License

No license has been specified yet. Unless a license is added to the repository, the project should not be assumed to be available for unrestricted reuse or redistribution.
