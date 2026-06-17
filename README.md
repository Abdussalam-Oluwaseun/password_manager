# Password Generator & Manager

A simple command-line password generator and encrypted password manager,

## Features

- **Generate** strong random passwords (configurable length and character sets)
- **Generate passphrases** (Diceware-style, easier to memorize)
- **Check strength** of any password (entropy estimate, common-password detection,
  sequence/repeat detection)
- **Store** site/username/password entries in an encrypted local vault
- **Retrieve, list, and delete** vault entries

## How the encryption works

- You set a **master password** once, when you run `init`.
- A random salt is generated and stored locally (the master password itself is *never* stored).
- PBKDF2-HMAC-SHA256 with 480,000 iterations derives a 256-bit encryption key from your
  master password + salt.
- Each stored password is encrypted individually with **Fernet** (AES-128-CBC + HMAC-SHA256,
  from the `cryptography` library) before being written to the local SQLite database (`vault.db`).
- Security rests entirely on your master password — if you forget it, the vault
  **cannot** be recovered. There's no backdoor by design (Kerckhoffs's principle: the
  algorithm is public, the key is the only secret).

## Setup

```bash
cd password_manager
pip install -r requirements.txt
python cli.py init
```

You'll be prompted to create and confirm a master password.

## Usage

**Generate a password:**
```bash
python cli.py generate --length 20
python cli.py generate --length 16 --no-symbols
python cli.py generate --exclude-ambiguous
```

**Generate a memorable passphrase:**
```bash
python cli.py passphrase --words 5
```

**Check the strength of a password:**
```bash
python cli.py check "MyP@ssw0rd123"
python cli.py check          # prompts securely without echoing input
```

**Generate and save directly to the vault:**
```bash
python cli.py generate --length 18 --save github.com --username myhandle
```

**Add an entry manually (you type the password):**
```bash
python cli.py add github.com --username myhandle
```

**Add an entry with an auto-generated password:**
```bash
python cli.py add github.com --username myhandle --generate --length 20
```

**Retrieve an entry:**
```bash
python cli.py get github.com
```

**List all stored sites (passwords are never shown in the list view):**
```bash
python cli.py list
```

**Delete an entry:**
```bash
python cli.py delete github.com
```

## Project structure

```
password_manager/
├── cli.py            # Command-line interface and argument parsing
├── generator.py       # Secure password / passphrase generation
├── strength.py         # Password strength scoring
├── vault.py             # Key derivation, encryption, SQLite storage
├── requirements.txt
└── README.md
```

## Notes / possible extensions

- Swap the SQLite backend for an encrypted file if you want zero dependencies on
  a database engine.
- Add a `tkinter` or web (Flask) front end on top of `vault.py` — the storage and
  crypto logic is fully decoupled from the CLI.
- Add password rotation reminders or breach-checking against a service like
  Have I Been Pwned's k-anonymity API.
- Add an "export" command that re-encrypts entries for backup, or a "change
  master password" command that re-derives the key and re-encrypts all entries.
