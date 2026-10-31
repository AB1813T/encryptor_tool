# src/encryptor_tool/kdf.py

import os
from argon2.low_level import hash_secret_raw, Type
from .constants import (
    SALT_SIZE, ARGON2_TIME_COST, ARGON2_MEMORY_COST, 
    ARGON2_PARALLELISM, KEY_LEN
)

def generate_salt() -> bytes:
    """Generates a cryptographically secure random salt."""
    return os.urandom(SALT_SIZE)

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 32-byte key from a password and salt using Argon2id.
    """
    if not password:
        raise ValueError("Password cannot be empty")
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt must be exactly {SALT_SIZE} bytes")

    # We use argon2.low_level to get raw bytes for our AES key
    # Argon2id (Type.ID) is the current industry standard
    key = hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LEN,
        type=Type.ID
    )
    return key