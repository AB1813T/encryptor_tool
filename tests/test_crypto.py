# tests/test_crypto.py

import os
import pytest
from src.encryptor_tool.crypto import encrypt_file, decrypt_file

@pytest.fixture
def sample_file(tmp_path):
    """Creates a temporary file with 150KB of random data."""
    file_path = tmp_path / "sample.bin"
    # 150KB is > 2 chunks (64KB each), so it tests our chunking logic
    data = os.urandom(150 * 1024) 
    file_path.write_bytes(data)
    return file_path, data

def test_encrypt_decrypt_roundtrip(tmp_path, sample_file):
    """Tests that a file can be encrypted and decrypted back to its original form."""
    input_path, original_data = sample_file
    enc_path = tmp_path / "sample.enc"
    dec_path = tmp_path / "sample.dec"

    # Encrypt
    encrypt_file(str(input_path), str(enc_path), "password123")
    assert enc_path.exists()

    # Decrypt
    decrypt_file(str(enc_path), str(dec_path), "password123")
    
    # Verify the decrypted data matches the original exactly
    assert dec_path.read_bytes() == original_data

def test_wrong_password(tmp_path, sample_file):
    """Tests that the wrong password fails and does not leave a decrypted file."""
    input_path, _ = sample_file
    enc_path = tmp_path / "sample.enc"
    dec_path = tmp_path / "sample.dec"

    encrypt_file(str(input_path), str(enc_path), "password123")
    
    with pytest.raises(ValueError, match="Authentication failed"):
        decrypt_file(str(enc_path), str(dec_path), "wrongpassword")
        
    assert not dec_path.exists()

def test_tamper_detection(tmp_path, sample_file):
    """Tests that modifying even 1 byte of the ciphertext causes decryption to fail."""
    input_path, _ = sample_file
    enc_path = tmp_path / "sample.enc"
    dec_path = tmp_path / "sample.dec"

    encrypt_file(str(input_path), str(enc_path), "password123")
    
    # Tamper with the file: flip the last byte of the ciphertext
    data = bytearray(enc_path.read_bytes())
    data[-1] ^= 0xFF  # XOR with 255 flips the byte
    enc_path.write_bytes(data)
    
    with pytest.raises(ValueError, match="Authentication failed"):
        decrypt_file(str(enc_path), str(dec_path), "password123")