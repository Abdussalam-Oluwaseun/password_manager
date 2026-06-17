"""
vault.py
Encrypted storage for password entries.

Security design:
- The user's master password is never stored.
- A random salt is generated once and stored alongside a "verifier" token.
- PBKDF2-HMAC-SHA256 (480,000 iterations) derives a 256-bit key from the
  master password + salt (per OWASP guidance for PBKDF2-SHA256, 2023).
- Fernet (AES-128-CBC + HMAC-SHA256, from the `cryptography` library)
  encrypts each stored password individually.
- Security rests entirely on the secrecy of the master password
  (Kerckhoffs's principle) — the algorithm itself is public and standard.
"""

import os
import sqlite3
import base64
import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.db")
VERIFIER_TEXT = b"vault-verification-token"
KDF_ITERATIONS = 480_000


def _derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL,
            verifier BLOB NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NOT NULL,
            username TEXT,
            encrypted_password BLOB NOT NULL,
            notes TEXT,
            UNIQUE(site, username)
        )
        """
    )
    conn.commit()
    return conn


def vault_exists() -> bool:
    if not os.path.exists(DB_PATH):
        return False
    conn = _get_connection()
    row = conn.execute("SELECT 1 FROM meta WHERE id = 1").fetchone()
    conn.close()
    return row is not None


def init_vault(master_password: str) -> None:
    if vault_exists():
        raise RuntimeError("Vault already initialized.")
    salt = os.urandom(16)
    key = _derive_key(master_password, salt)
    fernet = Fernet(key)
    verifier = fernet.encrypt(VERIFIER_TEXT)

    conn = _get_connection()
    conn.execute("INSERT INTO meta (id, salt, verifier) VALUES (1, ?, ?)", (salt, verifier))
    conn.commit()
    conn.close()


def unlock_vault(master_password: str) -> Fernet:
    if not vault_exists():
        raise RuntimeError("Vault not initialized. Run 'init' first.")
    conn = _get_connection()
    row = conn.execute("SELECT salt, verifier FROM meta WHERE id = 1").fetchone()
    conn.close()
    salt, verifier = row
    key = _derive_key(master_password, salt)
    fernet = Fernet(key)
    try:
        fernet.decrypt(verifier)
    except InvalidToken:
        raise ValueError("Incorrect master password.")
    return fernet


def add_entry(fernet: Fernet, site: str, username: str, password: str, notes: str = "") -> None:
    encrypted = fernet.encrypt(password.encode("utf-8"))
    conn = _get_connection()
    try:
        conn.execute(
            "INSERT INTO entries (site, username, encrypted_password, notes) VALUES (?, ?, ?, ?)",
            (site, username, encrypted, notes),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise ValueError(f"An entry for '{site}' with username '{username}' already exists.")
    finally:
        conn.close()


def get_entry(fernet: Fernet, site: str) -> list:
    conn = _get_connection()
    rows = conn.execute(
        "SELECT id, site, username, encrypted_password, notes FROM entries WHERE site = ?",
        (site,),
    ).fetchall()
    conn.close()

    results = []
    for row in rows:
        entry_id, site_name, username, encrypted_password, notes = row
        decrypted = fernet.decrypt(encrypted_password).decode("utf-8")
        results.append(
            {
                "id": entry_id,
                "site": site_name,
                "username": username,
                "password": decrypted,
                "notes": notes,
            }
        )
    return results


def list_entries() -> list:
    conn = _get_connection()
    rows = conn.execute("SELECT site, username, notes FROM entries ORDER BY site").fetchall()
    conn.close()
    return [{"site": r[0], "username": r[1], "notes": r[2]} for r in rows]


def delete_entry(site: str, username: str = None) -> int:
    conn = _get_connection()
    if username:
        cur = conn.execute("DELETE FROM entries WHERE site = ? AND username = ?", (site, username))
    else:
        cur = conn.execute("DELETE FROM entries WHERE site = ?", (site,))
    conn.commit()
    deleted = cur.rowcount
    conn.close()
    return deleted


def prompt_master_password(confirm: bool = False) -> str:
    pw = getpass.getpass("Master password: ")
    if confirm:
        pw2 = getpass.getpass("Confirm master password: ")
        if pw != pw2:
            raise ValueError("Passwords do not match.")
    return pw
