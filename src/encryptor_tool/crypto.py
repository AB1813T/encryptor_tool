# src/encryptor_tool/crypto.py

import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from .constants import (
    MAGIC, VERSION, ALGO_AES_GCM, BASE_NONCE_SIZE, CHUNK_SIZE
)
from .kdf import derive_key, generate_salt

def _build_header(salt: bytes, base_nonce: bytes) -> bytes:
    """Packs the unencrypted header bytes."""
    # 4 bytes magic + 1 byte version + 1 byte algo + 16 bytes salt + 8 bytes nonce = 30 bytes
    header = MAGIC + bytes([VERSION, ALGO_AES_GCM]) + salt + base_nonce
    assert len(header) == 30
    return header

def _parse_header(header_bytes: bytes):
    """Unpacks and validates the header."""
    if len(header_bytes) != 30:
        raise ValueError("Invalid header size")
    
    magic = header_bytes[0:4]
    version = header_bytes[4]
    algo = header_bytes[5]
    
    if magic != MAGIC:
        raise ValueError("Not a valid encryptor file (bad magic bytes)")
    if version != VERSION:
        raise ValueError(f"Unsupported version: {version}")
    if algo != ALGO_AES_GCM:
        raise ValueError(f"Unsupported algorithm: {algo}")
        
    salt = header_bytes[6:22]
    base_nonce = header_bytes[22:30]
    return salt, base_nonce

def encrypt_file(input_path: str, output_path: str, password: str):
    """Encrypts a file using chunked AES-256-GCM."""
    salt = generate_salt()
    base_nonce = os.urandom(BASE_NONCE_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    header = _build_header(salt, base_nonce)

    # Write to a temporary file first (Atomic Write)
    temp_path = output_path + ".tmp"
    
    try:
        with open(input_path, "rb") as f_in, open(temp_path, "wb") as f_out:
            # 1. Write the unencrypted header
            f_out.write(header)

            chunk_index = 0
            while True:
                # Read a 64KB chunk
                plaintext_chunk = f_in.read(CHUNK_SIZE)
                
                # If the file is empty, we still process the final chunk
                if not plaintext_chunk and chunk_index > 0:
                    break
                
                # Check if this is the last chunk
                next_chunk = f_in.read(1)
                is_final = (len(next_chunk) == 0)
                
                # If we read a byte, we need to seek back so we don't lose it
                if not is_final:
                    f_in.seek(-1, 1)
                
                # If this is the final chunk, append the anti-truncation marker
                if is_final:
                    plaintext_chunk += b"FINAL"

                # Construct the 12-byte nonce (8-byte base + 4-byte counter)
                nonce = base_nonce + struct.pack(">I", chunk_index)
                
                # Encrypt the chunk, passing the header as Associated Authenticated Data (AAD)
                ciphertext = aesgcm.encrypt(nonce, plaintext_chunk, header)
                
                # Write: 4-byte length + 12-byte nonce + ciphertext
                # (Note: the 16-byte GCM tag is automatically appended to the ciphertext)
                f_out.write(struct.pack(">I", len(ciphertext)))
                f_out.write(nonce)
                f_out.write(ciphertext)
                
                chunk_index += 1
                
                if is_final:
                    break

        # Atomic replace (overwrites if it exists)
        os.replace(temp_path, output_path)
        
    except Exception as e:
        # Clean up temp file on failure
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise e

def decrypt_file(input_path: str, output_path: str, password: str):
    """Decrypts a file using chunked AES-256-GCM."""
    temp_path = output_path + ".tmp"
    
    try:
        with open(input_path, "rb") as f_in:
            # 1. Read and parse the header
            header = f_in.read(30)
            salt, base_nonce = _parse_header(header)
            
            # 2. Derive key
            key = derive_key(password, salt)
            aesgcm = AESGCM(key)
            
            with open(temp_path, "wb") as f_out:
                chunk_index = 0
                
                while True:
                    # Read 4-byte chunk length
                    length_bytes = f_in.read(4)
                    if not length_bytes:
                        raise ValueError("File truncated unexpectedly (missing final chunk)")
                    
                    chunk_length = struct.unpack(">I", length_bytes)[0]
                    
                    # Read the 12-byte nonce and the rest of the ciphertext
                    nonce = f_in.read(12)
                    ciphertext = f_in.read(chunk_length)
                    
                    if len(ciphertext) != chunk_length:
                        raise ValueError("File truncated unexpectedly during chunk read")
                    
                    # Verify expected nonce matches the chunk index (prevents reordering)
                    expected_nonce = base_nonce + struct.pack(">I", chunk_index)
                    if nonce != expected_nonce:
                        raise ValueError("Chunk reordering detected!")

                    try:
                        # Decrypt the chunk (verifies the auth tag automatically)
                        plaintext_chunk = aesgcm.decrypt(nonce, ciphertext, header)
                    except InvalidTag:
                        raise ValueError("Authentication failed: Wrong password or file has been tampered with.")
                    
                    # Check for the anti-truncation marker
                    if plaintext_chunk.endswith(b"FINAL"):
                        # Remove the marker and write the final data
                        f_out.write(plaintext_chunk[:-5])
                        break # Reached the true end of the file
                    else:
                        f_out.write(plaintext_chunk)
                        
                    chunk_index += 1
                    
        # Atomic replace
        os.replace(temp_path, output_path)
        
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise e