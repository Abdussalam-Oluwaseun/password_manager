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
            verifier BLOB NOT NULL,
            encrypted_dek_primary BLOB,
            salt_secondary BLOB,
            verifier_secondary BLOB,
            encrypted_dek_secondary BLOB
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
            strength_score INTEGER,
            UNIQUE(site, username)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL,
            details TEXT
        )
        """
    )
    # Perform schema migrations for legacy databases
    try:
        conn.execute("ALTER TABLE meta ADD COLUMN encrypted_dek_primary BLOB")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE meta ADD COLUMN salt_secondary BLOB")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE meta ADD COLUMN verifier_secondary BLOB")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE meta ADD COLUMN encrypted_dek_secondary BLOB")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE entries ADD COLUMN strength_score INTEGER")
    except sqlite3.OperationalError:
        pass
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

    # Generate random Data Encryption Key (DEK)
    raw_dek = Fernet.generate_key()
    encrypted_dek_primary = fernet.encrypt(raw_dek)

    conn = _get_connection()
    conn.execute(
        "INSERT INTO meta (id, salt, verifier, encrypted_dek_primary) VALUES (1, ?, ?, ?)",
        (salt, verifier, encrypted_dek_primary)
    )
    conn.commit()
    conn.close()

    add_activity_log("Vault Created", "Initial master password vault set up successfully")


def unlock_vault(password: str, use_recovery: bool = False) -> Fernet:
    if not vault_exists():
        raise RuntimeError("Vault not initialized. Run 'init' first.")
    
    conn = _get_connection()
    if use_recovery:
        row = conn.execute("SELECT salt_secondary, verifier_secondary, encrypted_dek_secondary FROM meta WHERE id = 1").fetchone()
        conn.close()
        if not row or row[0] is None:
            raise ValueError("No recovery password set.")
        salt, verifier, encrypted_dek = row
    else:
        row = conn.execute("SELECT salt, verifier, encrypted_dek_primary FROM meta WHERE id = 1").fetchone()
        conn.close()
        salt, verifier, encrypted_dek = row
        
    key = _derive_key(password, salt)
    fernet = Fernet(key)
    try:
        fernet.decrypt(verifier)
    except InvalidToken:
        raise ValueError("Incorrect password.")
        
    # Check for legacy DEK migration
    if not use_recovery and encrypted_dek is None:
        # Migrate legacy vault to DEK-based encryption on-the-fly
        raw_dek = Fernet.generate_key()
        encrypted_dek_primary = fernet.encrypt(raw_dek)
        
        conn = _get_connection()
        rows = conn.execute("SELECT id, encrypted_password FROM entries").fetchall()
        from strength import check_strength
        for row_id, enc_pwd in rows:
            try:
                decrypted = fernet.decrypt(enc_pwd).decode("utf-8")
                strength_score = check_strength(decrypted)["score"]
                new_enc_pwd = Fernet(raw_dek).encrypt(decrypted.encode("utf-8"))
                conn.execute(
                    "UPDATE entries SET encrypted_password = ?, strength_score = ? WHERE id = ?",
                    (new_enc_pwd, strength_score, row_id)
                )
            except Exception:
                pass
                
        conn.execute("UPDATE meta SET encrypted_dek_primary = ? WHERE id = 1", (encrypted_dek_primary,))
        conn.commit()
        conn.close()
        
        add_activity_log("Vault Migrated", "Migrated legacy entries to DEK-based encryption")
        add_activity_log("Vault Unlocked", "Unlocked using master password")
        return Fernet(raw_dek)
    else:
        # Decrypt the DEK using derived key
        raw_dek = fernet.decrypt(encrypted_dek)
        
        # Check if any entries need strength_score backfilled (migration support)
        conn = _get_connection()
        null_rows = conn.execute("SELECT id, encrypted_password FROM entries WHERE strength_score IS NULL").fetchall()
        if null_rows:
            from strength import check_strength
            for row_id, enc_pwd in null_rows:
                try:
                    decrypted = Fernet(raw_dek).decrypt(enc_pwd).decode("utf-8")
                    strength_score = check_strength(decrypted)["score"]
                    conn.execute("UPDATE entries SET strength_score = ? WHERE id = ?", (strength_score, row_id))
                except Exception:
                    pass
            conn.commit()
        conn.close()
        
        if use_recovery:
            add_activity_log("Vault Unlocked", "Unlocked using recovery password")
        else:
            add_activity_log("Vault Unlocked", "Unlocked using master password")
            
        return Fernet(raw_dek)


def add_entry(fernet: Fernet, site: str, username: str, password: str, notes: str = "") -> None:
    from strength import check_strength
    strength_score = check_strength(password)["score"]
    encrypted = fernet.encrypt(password.encode("utf-8"))
    conn = _get_connection()
    try:
        conn.execute(
            "INSERT INTO entries (site, username, encrypted_password, notes, strength_score) VALUES (?, ?, ?, ?, ?)",
            (site, username, encrypted, notes, strength_score),
        )
        conn.commit()
        add_activity_log("Entry Created", f"Added credentials for {site} ({username})")
    except sqlite3.IntegrityError:
        raise ValueError(f"An entry for '{site}' with username '{username}' already exists.")
    finally:
        conn.close()


def get_entry(fernet: Fernet, site: str) -> list:
    conn = _get_connection()
    rows = conn.execute(
        "SELECT id, site, username, encrypted_password, notes, strength_score FROM entries WHERE site = ?",
        (site,),
    ).fetchall()
    conn.close()

    results = []
    for row in rows:
        entry_id, site_name, username, encrypted_password, notes, strength_score = row
        decrypted = fernet.decrypt(encrypted_password).decode("utf-8")
        results.append(
            {
                "id": entry_id,
                "site": site_name,
                "username": username,
                "password": decrypted,
                "notes": notes,
                "strength_score": strength_score,
            }
        )
    add_activity_log("Entry Decrypted", f"Viewed credentials for {site}")
    return results


def list_entries() -> list:
    conn = _get_connection()
    rows = conn.execute("SELECT site, username, notes, strength_score FROM entries ORDER BY site").fetchall()
    conn.close()
    return [{"site": r[0], "username": r[1], "notes": r[2], "strength_score": r[3]} for r in rows]


def delete_entry(site: str, username: str = None) -> int:
    conn = _get_connection()
    if username:
        cur = conn.execute("DELETE FROM entries WHERE site = ? AND username = ?", (site, username))
        details_str = f"Deleted credentials for {site} ({username})"
    else:
        cur = conn.execute("DELETE FROM entries WHERE site = ?", (site,))
        details_str = f"Deleted credentials for {site}"
    conn.commit()
    deleted = cur.rowcount
    conn.close()
    if deleted > 0:
        add_activity_log("Entry Deleted", details_str)
    return deleted


def update_master_password(old_password: str, new_password: str) -> None:
    if not vault_exists():
        raise RuntimeError("Vault not initialized.")
    
    conn = _get_connection()
    row = conn.execute("SELECT salt, encrypted_dek_primary FROM meta WHERE id = 1").fetchone()
    conn.close()
    salt, encrypted_dek_primary = row
    
    # Decrypt DEK with old password key
    old_key = _derive_key(old_password, salt)
    old_fernet = Fernet(old_key)
    try:
        raw_dek = old_fernet.decrypt(encrypted_dek_primary)
    except InvalidToken:
        raise ValueError("Incorrect old master password.")
        
    # Re-encrypt DEK with new password key
    new_salt = os.urandom(16)
    new_key = _derive_key(new_password, new_salt)
    new_fernet = Fernet(new_key)
    
    new_verifier = new_fernet.encrypt(VERIFIER_TEXT)
    new_encrypted_dek = new_fernet.encrypt(raw_dek)
    
    conn = _get_connection()
    conn.execute(
        "UPDATE meta SET salt = ?, verifier = ?, encrypted_dek_primary = ? WHERE id = 1",
        (new_salt, new_verifier, new_encrypted_dek),
    )
    conn.commit()
    conn.close()
    
    add_activity_log("Master Password Changed", "Updated primary master password")


def set_secondary_password_with_primary(master_password: str, secondary_password: str) -> None:
    if not vault_exists():
        raise RuntimeError("Vault not initialized.")
        
    conn = _get_connection()
    row = conn.execute("SELECT salt, encrypted_dek_primary FROM meta WHERE id = 1").fetchone()
    conn.close()
    salt, encrypted_dek_primary = row
    
    # Decrypt DEK with master password
    key_primary = _derive_key(master_password, salt)
    fernet_primary = Fernet(key_primary)
    try:
        raw_dek = fernet_primary.decrypt(encrypted_dek_primary)
    except InvalidToken:
        raise ValueError("Incorrect master password.")
        
    # Encrypt DEK with secondary password
    salt_secondary = os.urandom(16)
    key_secondary = _derive_key(secondary_password, salt_secondary)
    fernet_secondary = Fernet(key_secondary)
    verifier_secondary = fernet_secondary.encrypt(VERIFIER_TEXT)
    encrypted_dek_secondary = fernet_secondary.encrypt(raw_dek)
    
    conn = _get_connection()
    conn.execute(
        """
        UPDATE meta 
        SET salt_secondary = ?, verifier_secondary = ?, encrypted_dek_secondary = ? 
        WHERE id = 1
        """,
        (salt_secondary, verifier_secondary, encrypted_dek_secondary)
    )
    conn.commit()
    conn.close()
    
    add_activity_log("Recovery Password Set", "Secondary master password configured")


def update_master_password_with_recovery(recovery_password: str, new_primary_password: str) -> None:
    if not vault_exists():
        raise RuntimeError("Vault not initialized.")
        
    conn = _get_connection()
    row = conn.execute("SELECT salt_secondary, encrypted_dek_secondary FROM meta WHERE id = 1").fetchone()
    conn.close()
    salt_secondary, encrypted_dek_secondary = row
    if not salt_secondary:
        raise ValueError("No recovery password set.")
        
    # Decrypt DEK with recovery password
    key_secondary = _derive_key(recovery_password, salt_secondary)
    fernet_secondary = Fernet(key_secondary)
    try:
        raw_dek = fernet_secondary.decrypt(encrypted_dek_secondary)
    except InvalidToken:
        raise ValueError("Incorrect recovery password.")
        
    # Encrypt DEK with new primary password
    new_salt = os.urandom(16)
    new_key = _derive_key(new_primary_password, new_salt)
    new_fernet = Fernet(new_key)
    
    new_verifier = new_fernet.encrypt(VERIFIER_TEXT)
    new_encrypted_dek = new_fernet.encrypt(raw_dek)
    
    conn = _get_connection()
    conn.execute(
        "UPDATE meta SET salt = ?, verifier = ?, encrypted_dek_primary = ? WHERE id = 1",
        (new_salt, new_verifier, new_encrypted_dek)
    )
    conn.commit()
    conn.close()
    
    add_activity_log("Master Password Changed", "Reset primary master password using recovery password")


def add_activity_log(action: str, details: str = "") -> None:
    try:
        conn = _get_connection()
        conn.execute(
            "INSERT INTO activity_log (action, details) VALUES (?, ?)",
            (action, details)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_activity_logs(limit: int = 50) -> list:
    conn = _get_connection()
    rows = conn.execute(
        "SELECT timestamp, action, details FROM activity_log ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [{"timestamp": r[0], "action": r[1], "details": r[2]} for r in rows]


def prompt_master_password(confirm: bool = False) -> str:
    pw = getpass.getpass("Master password: ")
    if confirm:
        pw2 = getpass.getpass("Confirm master password: ")
        if pw != pw2:
            raise ValueError("Passwords do not match.")
    return pw
