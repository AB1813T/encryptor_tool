# encryptor

CLI tool for authenticated file encryption using AES-256-GCM with Argon2id key derivation and chunked streaming AEAD.

> **Status:** 🚧 Early development. Not yet audited — do not use for sensitive data.

## Planned features

- AES-256-GCM authenticated encryption
- Argon2id password-based key derivation
- Chunked streaming encryption (handles large files without loading into RAM)
- Versioned, authenticated file header
- Atomic writes and secret zeroization

## License

MIT — see [LICENSE](LICENSE).