# Architecture & Threat Model

## File Format (v1)
Every encrypted file consists of:
1. **Header (30 bytes):** Magic bytes, Version, Algorithm ID, Salt (16 bytes), Base Nonce (8 bytes).
2. **Data Chunks:** A sequence of chunks containing a 4-byte length, 12-byte nonce, and the AES-GCM ciphertext.

## Threat Model

### Defends Against:
- **At-Rest Attacks:** If a hard drive is stolen, the attacker cannot read the files without the password.
- **Tampering:** An attacker cannot modify the ciphertext or the unencrypted header without the GCM authentication tag failing.
- **Truncation:** An attacker cannot cut off the end of the file to hide data; the `FINAL` marker will be missing.
- **Chunk Swapping:** An attacker cannot reorder blocks of the file, as the chunk index is baked into the nonce.
- **Brute-Force (Password):** Argon2id forces attackers to use significant RAM, making GPU/ASIC cracking economically unviable.

### Does NOT Defend Against:
- **Compromised Endpoints:** If your computer has malware/keyloggers, the attacker can steal the password or the plaintext before it is encrypted.
- **Weak Passwords:** Argon2id slows down attacks, but it cannot save a password like `123456`.
- **SSD Secure-Delete:** The `--shred` feature overwrites files on disk, but modern SSDs and Copy-on-Write filesystems (like APFS or ZFS) use wear-leveling. The original data blocks may still exist and require full-disk encryption or ATA Secure Erase to destroy.