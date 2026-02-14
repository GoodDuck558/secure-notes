Secure notes is a command-line encrypted note storage system written in Python. It allows users to securely store, retrieve, list, rename, and delete notes using strong cryptography derived from a master password.

All note contents are encrypted using authenticated encryption, and no plaintext notes are ever stored on disk.

Features:

Strong encryption using Fernet (AES-128 in CBC with HMAC authentication)

Secure key derivation using PBKDF2-HMAC-SHA256 with configurable iterations

Master password protection

Multiple note support

Add, view, list, rename, and delete notes

Integrity protection against tampering

Automatic vault and notes folder creation

No plaintext storage of sensitive data

Minimal dependencies and lightweight design
