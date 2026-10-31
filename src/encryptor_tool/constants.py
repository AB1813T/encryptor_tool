# src/encryptor_tool/constants.py

# File Format Identifiers
MAGIC = b"ENC1"
VERSION = 1
ALGO_AES_GCM = 1

# Sizes
SALT_SIZE = 16
BASE_NONCE_SIZE = 8
CHUNK_SIZE = 64 * 1024  # 64 KiB
TAG_SIZE = 16

# Argon2id Parameters (Tuned for security vs. speed ~0.5-1s)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
KEY_LEN = 32  # 256-bit key for AES-256
