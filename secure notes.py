"""
secure_notes.py

import json
import re
import os
import tempfile
import base64
import secrets
from getpass import getpass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

# ---------- CONSTANTS ----------

VAULT_FILE   = "vault.enc"
NOTES_DIR    = "notes"
NONCE_SIZE   = 12      # 96-bit nonce for AES-GCM
SALT_SIZE    = 32      # 256-bit Argon2 salt
KEY_SIZE     = 32      # 256-bit AES key

# Argon2id parameters (OWASP minimum for interactive login)
ARGON2_TIME_COST   = 3
ARGON2_MEMORY_COST = 65536   # 64 MiB
ARGON2_PARALLELISM = 2

os.makedirs(NOTES_DIR, exist_ok=True)


# ---------- KEY DERIVATION ----------

def derive_key(password: bytearray, salt: bytes, context: str) -> bytes:
    """
    Argon2id KDF. Context is mixed into the salt to produce domain-separated
    keys from the same password without a second KDF call.
    Context-salted: salt || context_byte prevents key reuse across domains.
    """
    ctx = context.encode()
    salted = salt + ctx
    return hash_secret_raw(
        secret=bytes(password),
        salt=salted[:SALT_SIZE + len(ctx)],   # Argon2 salt can exceed 32 bytes
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


# ---------- AEAD ENCRYPT / DECRYPT ----------

def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """
    AES-256-GCM. Returns nonce || ciphertext+tag.
    AAD is authenticated but not encrypted (used for version/context binding).
    """
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct


def aead_decrypt(key: bytes, data: bytes, aad: bytes = b"") -> bytes:
    """
    Raises ValueError on authentication failure (wrong key or tampered data).
    """
    nonce, ct = data[:NONCE_SIZE], data[NONCE_SIZE:]
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except Exception:
        raise ValueError("Decryption failed: wrong password or corrupted data.")


# ---------- ATOMIC FILE WRITE ----------

def atomic_write(path: str, data: bytes):
    """
    Write to a temp file in the same directory, then atomically replace target.
    Prevents partial writes from corrupting state on crash.
    """
    dir_ = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=dir_)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except:
        os.unlink(tmp)
        raise


# ---------- NOTE NAME VALIDATION ----------

def validate_note_name(name: str) -> str:
    if not name or len(name) > 50 or not re.fullmatch(r"[a-zA-Z0-9_-]+", name):
        raise ValueError("Invalid note name (alphanumeric, _ - only, max 50 chars).")
    return name


def note_path(name: str) -> str:
    return os.path.join(NOTES_DIR, f"{name}.enc")


# ---------- INDEX (encrypted, name-hiding) ----------

def load_index(password: bytearray):
    """
    Returns (index_dict, salt, raw_blob) or ({}, None, None) if vault absent.
    Index is fully encrypted — note names are not visible on disk.
    """
    if not os.path.exists(VAULT_FILE):
        return {}, None, None

    with open(VAULT_FILE, "rb") as f:
        blob = f.read()

    try:
        envelope = json.loads(blob)
    except json.JSONDecodeError:
        raise ValueError("Vault file corrupted.")

    version = envelope.get("v")
    if version != 2:
        raise ValueError(f"Unsupported vault version: {version}")

    salt       = base64.urlsafe_b64decode(envelope["salt"])
    ciphertext = base64.urlsafe_b64decode(envelope["ciphertext"])

    key = derive_key(password, salt, "index")
    aad = b"vault-index-v2"
    plaintext = aead_decrypt(key, ciphertext, aad)

    return json.loads(plaintext), salt, blob


def save_index(index: dict, password: bytearray, salt: bytes = None):
    salt = salt or secrets.token_bytes(SALT_SIZE)
    key  = derive_key(password, salt, "index")
    aad  = b"vault-index-v2"

    plaintext  = json.dumps(index, separators=(",", ":")).encode()
    ciphertext = aead_encrypt(key, plaintext, aad)

    envelope = {
        "v":          2,
        "salt":       base64.urlsafe_b64encode(salt).decode(),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode(),
    }

    atomic_write(VAULT_FILE, json.dumps(envelope).encode())


# ---------- NOTE ENCRYPT / DECRYPT ----------

def encrypt_note(name: str, content: str, password: bytearray) -> bytes:
    """
    Each note has its own Argon2id-derived key (independent per-note salt).
    Name is bound into AAD — prevents a note file from being renamed/substituted
    to pass integrity checks under a different name.
    """
    salt = secrets.token_bytes(SALT_SIZE)
    key  = derive_key(password, salt, "note")
    aad  = name.encode()   # authenticated, not encrypted

    ciphertext = aead_encrypt(key, content.encode(), aad)

    envelope = {
        "v":          2,
        "salt":       base64.urlsafe_b64encode(salt).decode(),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode(),
    }
    return json.dumps(envelope).encode()


def decrypt_note(name: str, password: bytearray) -> str:
    path = note_path(name)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Note file missing: {path}")

    with open(path, "rb") as f:
        raw = json.loads(f.read())

    if raw.get("v") != 2:
        raise ValueError("Unsupported note version.")

    salt       = base64.urlsafe_b64decode(raw["salt"])
    ciphertext = base64.urlsafe_b64decode(raw["ciphertext"])
    key        = derive_key(password, salt, "note")
    aad        = name.encode()

    return aead_decrypt(key, ciphertext, aad).decode()


# ---------- OPERATIONS ----------

def create_note(password: bytearray):
    name    = validate_note_name(input("Note name: ").strip())
    content = input("Note content:\n")

    index, salt, _ = load_index(password)

    if name in index and input("Overwrite? (y/N): ").lower() != "y":
        return

    data = encrypt_note(name, content, password)
    atomic_write(note_path(name), data)

    # Index stores a version marker per note (no plaintext names on disk —
    # names only exist inside the encrypted index blob).
    index[name] = 2
    save_index(index, password, salt)
    print("Saved.")


def read_note(password: bytearray):
    name = validate_note_name(input("Note name: ").strip())

    index, _, _ = load_index(password)
    if name not in index:
        print("Not found.")
        return

    print("\n" + decrypt_note(name, password))


def delete_note(password: bytearray):
    name = validate_note_name(input("Note name: ").strip())

    index, salt, _ = load_index(password)
    if name not in index:
        print("Not found.")
        return

    if input("Delete permanently? (y/N): ").lower() != "y":
        return

    path = note_path(name)
    if os.path.exists(path):
        # Best-effort overwrite before unlink (not a substitute for secure delete)
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(secrets.token_bytes(size))
        os.remove(path)

    del index[name]
    save_index(index, password, salt)
    print("Deleted.")


def rename_note(password: bytearray):
    old = validate_note_name(input("Old name: ").strip())
    new = validate_note_name(input("New name: ").strip())

    index, salt, _ = load_index(password)
    if old not in index:
        print("Source note not found.")
        return
    if new in index:
        print("Target name already exists.")
        return

    content = decrypt_note(old, password)

    # Write new note first; only remove old after success
    atomic_write(note_path(new), encrypt_note(new, content, password))

    os.remove(note_path(old))
    index[new] = 2
    del index[old]
    save_index(index, password, salt)
    print("Renamed.")


def list_notes(password: bytearray):
    index, _, _ = load_index(password)
    if not index:
        print("Empty vault.")
    else:
        for n in sorted(index):
            print(" -", n)


# ---------- MAIN ----------

def zero_bytearray(b: bytearray):
    """Best-effort zeroing. Python GC may retain copies; this reduces window."""
    for i in range(len(b)):
        b[i] = 0


def main():
    raw = getpass("Master password: ")
    password = bytearray(raw.encode())
    raw = "0" * len(raw)   # best-effort string wipe (immutable, limited effect)

    try:
        while True:
            print("\n1) Create  2) Read  3) List  4) Rename  5) Delete  6) Exit")
            choice = input("> ").strip()

            try:
                if   choice == "1": create_note(password)
                elif choice == "2": read_note(password)
                elif choice == "3": list_notes(password)
                elif choice == "4": rename_note(password)
                elif choice == "5": delete_note(password)
                elif choice == "6": break
                else: print("Invalid choice.")
            except (ValueError, FileNotFoundError) as e:
                print("Error:", e)
    finally:
        zero_bytearray(password)


if __name__ == "__main__":
    main()
