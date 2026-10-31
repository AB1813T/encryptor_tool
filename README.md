# encryptor_tool

A secure, streaming Command Line Interface (CLI) for authenticated file encryption using **AES-256-GCM** and **Argon2id**.

> **Status:** 🚧 Educational / Portfolio project. This code has not been professionally audited. Do not use it to protect life-critical or highly sensitive data.

## 🔒 Security Features

- **Authenticated Encryption (AEAD):** Uses AES-256-GCM to ensure both confidentiality and integrity. If a single byte of the ciphertext is modified, decryption fails.
- **Memory-Hard Key Derivation:** Uses Argon2id (with tuned memory/time parameters) to protect against GPU-accelerated brute-force attacks on passwords.
- **Streaming & Chunking:** Files are processed in 64KB chunks. This allows encryption/decryption of massive files (e.g., 10GB+) without exhausting system RAM.
- **Nonce Reordering Protection:** Each chunk uses a derived nonce based on the base nonce and the chunk index. Swapping or reordering chunks causes a decryption failure.
- **Truncation Detection:** The final chunk contains a special sentinel marker. If the file is truncated (cut short), the tool detects it and deletes the partial output.
- **Authenticated Header:** The unencrypted file header (containing the salt and algorithm IDs) is passed as Additional Authenticated Data (AAD), preventing parameter-tampering attacks.
- **Atomic Writes:** Data is written to a `.tmp` file and atomically renamed only upon success. If the process crashes, no corrupt files are left behind.

## 🚀 Installation

Ensure you have Python 3.10+ installed.

```bash
# Clone the repository
git clone git@github.com:AB1813T/encryptor_tool.git
cd encryptor_tool

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install the tool in editable mode
pip install -e .



💻 Usage

Encrypt a file (prompts for a password securely):
encryptor-tool encrypt my_secret_document.pdf
# Output: my_secret_document.pdf.enc


Decrypt a file:
encryptor-tool decrypt my_secret_document.pdf.enc
# Output: my_secret_document.pdf

Overwrite an existing file:
By default, the tool will not overwrite existing files to prevent accidental data loss.

Use -f or --force to overwrite an existing file:
encryptor-tool decrypt my_secret_document.pdf.enc -f

Securely shred the original file:
Add the -s or --shred flag to overwrite the source file with random data 3 times before deleting it. This works for both encryption (destroys plaintext) and decryption (destroys ciphertext).


encryptor-tool encrypt my_secret_document.pdf --shred
encryptor-tool decrypt my_secret_document.pdf.enc --shred

🧪 Testing
This project uses pytest to verify the cryptographic properties, including successful roundtrips, wrong-password rejection, and tamper detection.

pip install pytest
pytest tests/


📖 Design & Threat Model
See DESIGN.md for a deep dive into the file format and cryptographic decisions.


📄 License
MIT — see LICENSE.