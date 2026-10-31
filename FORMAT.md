# Encryptor File Format (v1)

All integer values are unsigned and big-endian (network byte order).

## 1. File Header (Unencrypted)
The file starts with a fixed-size header that tells the tool how to decrypt it.

| Field | Size (Bytes) | Description |
|---|---|---|
| Magic Bytes | 4 | Always `ENC1` (0x45 0x4E 0x43 0x31) to identify the file type. |
| Version | 1 | Currently `0x01`. |
| Algorithm | 1 | `0x01` = AES-256-GCM. `0x02` = ChaCha20-Poly1305 (Future). |
| Salt | 16 | Randomly generated salt for Argon2id key derivation. |
| Base Nonce | 8 | Randomly generated 8-byte prefix for chunk nonces. |

*Total Header Size: 30 bytes.*

## 2. Data Chunks (Streamed)
After the header, the file is divided into encrypted chunks. 
To prevent loading huge files into RAM, we process the file in **64 KiB (65,536 byte) chunks**.

For each chunk, we write:
| Field | Size (Bytes) | Description |
|---|---|---|
| Chunk Length | 4 | The length of the encrypted chunk (plaintext length + 16 byte auth tag). |
| Nonce | 12 | The 8-byte Base Nonce + a 4-byte counter (starts at 0, increments per chunk). |
| Ciphertext | Variable | The encrypted data. |
| Auth Tag | 16 | The GCM authentication tag (appended to the ciphertext by the crypto library). |

## 3. Final Chunk (Anti-Truncation)
If an attacker deletes the end of the file, how do we know? 
We add a special **Final Chunk** at the very end. 
The plaintext for this final chunk is exactly the string `FINAL`. 
If the decryption process reaches the end of the file and the final chunk does not decrypt to `FINAL`, the tool aborts and deletes the output file.

## 4. Authenticated Data (AAD)
To prevent tampering, the **File Header** (Magic + Version + Algorithm + Salt + Base Nonce) is passed into the GCM algorithm as Additional Authenticated Data (AAD) for every chunk. If an attacker changes the salt or algorithm, decryption fails immediately.