import json
import re
import hashlib
import base64
import os
from getpass import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

VAULT_FILE = "vault.enc"
DEFAULT_ITERATIONS = 200_000
SALT_SIZE = 16


# -------------------- UTIL --------------------

def validate_note_name(name: str):
    if not name or len(name) > 50 or not re.fullmatch(r"[a-zA-Z0-9_-]+", name):
        raise ValueError("Invalid note name.")
    return name


def stream_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()


def derive_key(password: str, salt: bytes, context: str, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    material = (context + password).encode()
    return base64.urlsafe_b64encode(kdf.derive(material))


def encrypt(plaintext: str, key: bytes) -> bytes:
    return Fernet(key).encrypt(plaintext.encode())


def decrypt(ciphertext: bytes, key: bytes) -> str:
    try:
        return Fernet(key).decrypt(ciphertext).decode()
    except InvalidToken:
        raise ValueError("Wrong password or corrupted data")


# -------------------- INDEX --------------------

def load_index(password: str):
    if not os.path.exists(VAULT_FILE):
        return {}, None, None

    raw = json.loads(open(VAULT_FILE, "rb").read())
    salt = base64.urlsafe_b64decode(raw["salt"])
    iterations = raw["iterations"]
    key = derive_key(password, salt, "index", iterations)
    plaintext = decrypt(base64.urlsafe_b64decode(raw["ciphertext"]), key)
    return json.loads(plaintext), salt, iterations


def save_index(index: dict, password: str, salt=None, iterations=None):
    salt = salt or os.urandom(SALT_SIZE)
    iterations = iterations or DEFAULT_ITERATIONS
    key = derive_key(password, salt, "index", iterations)
    ciphertext = encrypt(json.dumps(index, separators=(",", ":")), key)

    data = {
        "v": 1,
        "salt": base64.urlsafe_b64encode(salt).decode(),
        "iterations": iterations,
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode()
    }

    with open(VAULT_FILE, "wb") as f:
        f.write(json.dumps(data).encode())


# -------------------- NOTES --------------------

def encrypt_note(name: str, content: str, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt, "note", DEFAULT_ITERATIONS)
    payload = f"{name}\n{content}"
    encrypted = encrypt(payload, key)

    return json.dumps({
        "v": 1,
        "salt": base64.urlsafe_b64encode(salt).decode(),
        "iterations": DEFAULT_ITERATIONS,
        "ciphertext": base64.urlsafe_b64encode(encrypted).decode()
    }).encode()


def decrypt_note(name: str, password: str) -> str:
    raw = json.loads(open(f"{name}.enc", "rb").read())
    salt = base64.urlsafe_b64decode(raw["salt"])
    key = derive_key(password, salt, "note", raw["iterations"])
    plaintext = decrypt(base64.urlsafe_b64decode(raw["ciphertext"]), key)

    if not plaintext.startswith(name + "\n"):
        raise ValueError("Metadata mismatch")

    return plaintext[len(name) + 1:]


# -------------------- OPERATIONS --------------------

def create_note(password):
    name = validate_note_name(input("Note name: ").strip())
    content = input("Note content:\n")

    index, salt, iters = load_index(password)
    if name in index:
        if input("Overwrite? (y/N): ").lower() != "y":
            return

    data = encrypt_note(name, content, password)
    with open(f"{name}.enc", "wb") as f:
        f.write(data)

    index[name] = stream_sha256(f"{name}.enc")
    save_index(index, password, salt, iters)
    print("Saved.")


def read_note(password):
    name = validate_note_name(input("Note name: ").strip())
    index, _, _ = load_index(password)

    if name not in index:
        print("Not found.")
        return

    if stream_sha256(f"{name}.enc") != index[name]:
        print("Integrity check failed.")
        return

    print("\n" + decrypt_note(name, password))


def delete_note(password):
    name = validate_note_name(input("Note name: ").strip())
    index, salt, iters = load_index(password)

    if name not in index:
        print("Not found.")
        return

    if input("Delete permanently? (y/N): ").lower() != "y":
        return

    os.remove(f"{name}.enc")
    del index[name]
    save_index(index, password, salt, iters)
    print("Deleted.")


def rename_note(password):
    old = validate_note_name(input("Old name: ").strip())
    new = validate_note_name(input("New name: ").strip())

    index, salt, iters = load_index(password)
    if old not in index or new in index:
        print("Invalid rename.")
        return

    content = decrypt_note(old, password)
    os.remove(f"{old}.enc")

    with open(f"{new}.enc", "wb") as f:
        f.write(encrypt_note(new, content, password))

    del index[old]
    index[new] = stream_sha256(f"{new}.enc")
    save_index(index, password, salt, iters)
    print("Renamed.")


def list_notes(password):
    index, _, _ = load_index(password)
    if not index:
        print("Empty vault.")
    else:
        for n in index:
            print("-", n)


# -------------------- MAIN LOOP --------------------

def main():
    password = getpass("Master password: ")

    while True:
        print("""
1) Create note
2) Read note
3) List notes
4) Rename note
5) Delete note
6) Exit
""")
        choice = input("> ").strip()

        try:
            if choice == "1":
                create_note(password)
            elif choice == "2":
                read_note(password)
            elif choice == "3":
                list_notes(password)
            elif choice == "4":
                rename_note(password)
            elif choice == "5":
                delete_note(password)
            elif choice == "6":
                break
            else:
                print("Invalid choice.")
        except Exception as e:
            print("Error:", e)


if __name__ == "__main__":
    main()
