# Python Password Vault

A real local password manager with strong encryption.

## Features
- Master password → PBKDF2 key derivation (390k iterations)
- AES-GCM encryption of the entire vault
- Generate strong random passwords
- Add / get / list / delete entries
- Vault stored as a single encrypted file (`vault.enc`)

## Install
```bash
pip install -r requirements.txt
```

## Usage
```bash
# First time
python vault.py init

# Add an entry (can auto-generate password)
python vault.py add

# List all
python vault.py list

# Show one
python vault.py get github

# Delete
python vault.py delete github

# Just generate a password (no vault needed)
python vault.py gen 24
```

**Important:** Remember your master password. There is no recovery.
