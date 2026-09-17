#!/usr/bin/env python3
"""
Local Password Vault
- Master password derived key (PBKDF2)
- AES-GCM encryption for the vault file
- Generate strong passwords
- Add / get / list / delete entries
"""

import json
import os
import sys
import getpass
import secrets
import string
from pathlib import Path
from base64 import b64encode, b64decode

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

VAULT_FILE = Path(__file__).parent / "vault.enc"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_LEN = 32
ITERATIONS = 390_000

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt(data: dict, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    plaintext = json.dumps(data).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext

def decrypt(blob: bytes, password: str) -> dict:
    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))

def load_vault(password: str) -> dict:
    if not VAULT_FILE.exists():
        return {}
    blob = VAULT_FILE.read_bytes()
    try:
        return decrypt(blob, password)
    except Exception:
        print("Wrong master password or corrupted vault.")
        sys.exit(1)

def save_vault(data: dict, password: str):
    blob = encrypt(data, password)
    VAULT_FILE.write_bytes(blob)

def generate_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))

def get_master() -> str:
    return getpass.getpass("Master password: ")

def cmd_init():
    if VAULT_FILE.exists():
        print("Vault already exists.")
        return
    pw = getpass.getpass("Create master password: ")
    pw2 = getpass.getpass("Confirm: ")
    if pw != pw2:
        print("Passwords do not match.")
        return
    if len(pw) < 8:
        print("Master password should be at least 8 characters.")
        return
    save_vault({}, pw)
    print("Vault created successfully.")

def cmd_add(password: str):
    data = load_vault(password)
    name = input("Entry name (e.g. github): ").strip()
    if not name:
        print("Name required.")
        return
    if name in data:
        print("Entry already exists. Use a different name or delete first.")
        return
    user = input("Username / email: ").strip()
    gen = input("Generate password? [Y/n]: ").strip().lower()
    if gen in ("", "y", "yes"):
        length = input("Length [20]: ").strip() or "20"
        try:
            length = int(length)
        except ValueError:
            length = 20
        pwd = generate_password(length)
        print(f"Generated: {pwd}")
    else:
        pwd = getpass.getpass("Password: ")
    notes = input("Notes (optional): ").strip()
    data[name] = {"user": user, "password": pwd, "notes": notes}
    save_vault(data, password)
    print(f"Saved entry '{name}'.")

def cmd_get(password: str, name: str):
    data = load_vault(password)
    if name not in data:
        print("Entry not found.")
        return
    entry = data[name]
    print(f"\nName     : {name}")
    print(f"User     : {entry.get('user', '')}")
    print(f"Password : {entry.get('password', '')}")
    if entry.get("notes"):
        print(f"Notes    : {entry['notes']}")
    print()

def cmd_list(password: str):
    data = load_vault(password)
    if not data:
        print("Vault is empty.")
        return
    print("\nEntries:")
    for name in sorted(data.keys()):
        user = data[name].get("user", "")
        print(f"  • {name}  ({user})")
    print()

def cmd_delete(password: str, name: str):
    data = load_vault(password)
    if name not in data:
        print("Entry not found.")
        return
    confirm = input(f"Delete '{name}'? [y/N]: ").strip().lower()
    if confirm == "y":
        del data[name]
        save_vault(data, password)
        print("Deleted.")
    else:
        print("Cancelled.")

def cmd_gen():
    length = 20
    if len(sys.argv) > 2:
        try:
            length = int(sys.argv[2])
        except ValueError:
            pass
    print(generate_password(length))

def main():
    if len(sys.argv) < 2:
        print("""Password Vault
===============
Commands:
  init                 Create a new vault
  add                  Add a new entry
  get <name>           Show an entry
  list                 List all entries
  delete <name>        Delete an entry
  gen [length]         Generate a strong password (no vault needed)
""")
        return

    cmd = sys.argv[1].lower()

    if cmd == "init":
        cmd_init()
    elif cmd == "gen":
        cmd_gen()
    elif cmd in ("add", "get", "list", "delete"):
        master = get_master()
        if cmd == "add":
            cmd_add(master)
        elif cmd == "get":
            if len(sys.argv) < 3:
                print("Usage: vault.py get <name>")
                return
            cmd_get(master, sys.argv[2])
        elif cmd == "list":
            cmd_list(master)
        elif cmd == "delete":
            if len(sys.argv) < 3:
                print("Usage: vault.py delete <name>")
                return
            cmd_delete(master, sys.argv[2])
    else:
        print("Unknown command.")

if __name__ == "__main__":
    main()
