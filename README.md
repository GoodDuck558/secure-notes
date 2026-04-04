# Secure Notes

A command-line encrypted note storage system written in Python. Store, retrieve, list, rename, and delete notes protected by a master password. No plaintext is ever written to disk.

## Features

- **AES-256-GCM** authenticated encryption — confidentiality and integrity in a single primitive
- **Argon2id** key derivation — memory-hard, GPU-resistant, resistant to brute-force
- **Encrypted metadata** — note names are stored inside the encrypted vault index, not exposed on disk
- **Per-note keys** — each note is encrypted with an independently derived key and salt
- **Name binding via AAD** — note files are cryptographically bound to their names; substitution attacks fail authentication
- **Atomic writes** — all file operations use write-to-temp + replace, preventing corruption on crash
- **Best-effort password zeroing** — master password held in a zeroed bytearray, reducing in-memory exposure window
- **Input validation** — note names restricted to alphanumeric, `_`, and `-` characters
- **No plaintext on disk** — vault index and all note content are encrypted at rest

## Security Design

| Layer | Implementation |
|---|---|
| Symmetric encryption | AES-256-GCM |
| Key derivation | Argon2id (64 MiB, 3 iterations, parallelism 2) |
| Nonce | 96-bit random per encryption |
| Salt | 256-bit random per key |
| Domain separation | Context string mixed into KDF salt (`"index"` / `"note"`) |
| Integrity | GCM authentication tag (per ciphertext) |
| Metadata protection | Note names encrypted inside vault index |

## Dependencies

```
cryptography
argon2-cffi
```

Install with:

```bash
pip install cryptography argon2-cffi
```

## Usage

```bash
python secure_notes.py
```

You will be prompted for your master password. The vault is created automatically on first use.

```
1) Create  2) Read  3) List  4) Rename  5) Delete  6) Exit
```

## File Structure

```
secure_notes.py   # Main script
vault.enc         # Encrypted index (created on first use)
notes/            # Encrypted note files (created on first use)
```

## Known Limitations

- **Filename exposure** — note filenames on disk (`notes/<name>.enc`) still reflect note names. The encrypted index hides names from the vault, but the filesystem does not. If note names are sensitive, consider randomizing filenames (UUID mapping inside the index).
- **Password memory safety** — Python strings are immutable and cannot be reliably zeroed. The bytearray zeroing is best-effort; the GC may retain copies. This is a Python language limitation, not a design flaw.
- **No multi-user support** — single master password only.
- **No key rotation** — changing the master password requires decrypting and re-encrypting all notes manually.
