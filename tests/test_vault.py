import unittest
import os
import tempfile
import sqlite3
import vault

class TestVault(unittest.TestCase):
    def setUp(self):
        """Create a temporary database file path and override vault.DB_PATH."""
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.db_fd)
        # Remove the temp file so vault init can run cleanly (which expects no file or empty database)
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
            
        # Store original DB path to restore later
        self.original_db_path = vault.DB_PATH
        vault.DB_PATH = self.db_path

    def tearDown(self):
        """Restore original DB path and delete the temporary database file."""
        vault.DB_PATH = self.original_db_path
        if os.path.exists(self.db_path):
            # Try to close any active sqlite connection first if needed
            try:
                os.remove(self.db_path)
            except OSError:
                pass

    def test_vault_not_exists_initially(self):
        """Test vault_exists() returns False on clean setup."""
        self.assertFalse(vault.vault_exists())

    def test_init_vault_and_exists(self):
        """Test initializing the vault and checking its existence."""
        vault.init_vault("master_secret_123")
        self.assertTrue(vault.vault_exists())
        
        # Initializing again should fail
        with self.assertRaises(RuntimeError):
            vault.init_vault("another_password")

    def test_unlock_vault_success_and_failure(self):
        """Test unlock credentials verification."""
        password = "master_secret_123"
        vault.init_vault(password)
        
        # Unlock with correct password
        fernet = vault.unlock_vault(password)
        self.assertIsNotNone(fernet)
        
        # Unlock with incorrect password
        with self.assertRaises(ValueError):
            vault.unlock_vault("wrong_password")

    def test_unlock_uninitialized_vault(self):
        """Test unlocking before initialization raises an error."""
        with self.assertRaises(RuntimeError):
            vault.unlock_vault("any_password")

    def test_add_get_list_delete_entries(self):
        """Test CRUD operations on passwords vault."""
        password = "master_secret_123"
        vault.init_vault(password)
        fernet = vault.unlock_vault(password)

        # Initially empty list
        self.assertEqual(vault.list_entries(), [])

        # Add first entry
        vault.add_entry(fernet, "github.com", "user1", "gitpass123", "personal git")
        
        # Verify listed entries (does not include decrypted password)
        entries = vault.list_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["site"], "github.com")
        self.assertEqual(entries[0]["username"], "user1")
        self.assertEqual(entries[0]["notes"], "personal git")

        # Get detailed entry (includes decrypted password)
        details = vault.get_entry(fernet, "github.com")
        self.assertEqual(len(details), 1)
        self.assertEqual(details[0]["password"], "gitpass123")

        # Add another entry for same site, different username
        vault.add_entry(fernet, "github.com", "user2", "gitpass456", "work git")
        details = vault.get_entry(fernet, "github.com")
        self.assertEqual(len(details), 2)
        
        # Add duplicate site & username should fail integrity check
        with self.assertRaises(ValueError):
            vault.add_entry(fernet, "github.com", "user1", "another_pass")

        # Delete specific username entry
        deleted_count = vault.delete_entry("github.com", username="user1")
        self.assertEqual(deleted_count, 1)
        self.assertEqual(len(vault.get_entry(fernet, "github.com")), 1)

        # Delete remaining entry by site name only
        deleted_count = vault.delete_entry("github.com")
        self.assertEqual(deleted_count, 1)
        self.assertEqual(len(vault.get_entry(fernet, "github.com")), 0)

    def test_update_master_password(self):
        """Test updating the master password and re-encrypting data."""
        old_password = "old_secret_123"
        new_password = "new_secret_456"
        
        vault.init_vault(old_password)
        fernet_old = vault.unlock_vault(old_password)
        
        # Add some entries
        vault.add_entry(fernet_old, "google.com", "testuser", "googlepass", "search engine")
        vault.add_entry(fernet_old, "amazon.com", "shopuser", "amazonpass", "shopping")

        # Change master password
        vault.update_master_password(old_password, new_password)

        # Old password should now fail to unlock
        with self.assertRaises(ValueError):
            vault.unlock_vault(old_password)

        # New password should unlock
        fernet_new = vault.unlock_vault(new_password)
        self.assertIsNotNone(fernet_new)

        # Entries should be correctly decrypted using the new key
        google_details = vault.get_entry(fernet_new, "google.com")
        self.assertEqual(google_details[0]["password"], "googlepass")
        amazon_details = vault.get_entry(fernet_new, "amazon.com")
        self.assertEqual(amazon_details[0]["password"], "amazonpass")

    def test_recovery_password_flow(self):
        """Test configuring and unlocking with secondary/recovery password, then resetting primary."""
        primary_password = "primarypassword123"
        recovery_password = "recoverypassword456"
        new_primary = "newprimarypwd789"
        
        vault.init_vault(primary_password)
        fernet = vault.unlock_vault(primary_password)
        vault.add_entry(fernet, "facebook.com", "fbuser", "fbpassword")
        
        # Configure recovery password
        vault.set_secondary_password_with_primary(primary_password, recovery_password)
        
        # Try unlocking with incorrect recovery password
        with self.assertRaises(ValueError):
            vault.unlock_vault("wrongrecovery", use_recovery=True)
            
        # Unlock with correct recovery password
        fernet_rec = vault.unlock_vault(recovery_password, use_recovery=True)
        self.assertIsNotNone(fernet_rec)
        
        # Verify decrypted password works
        details = vault.get_entry(fernet_rec, "facebook.com")
        self.assertEqual(details[0]["password"], "fbpassword")
        
        # Reset primary password using recovery password
        vault.update_master_password_with_recovery(recovery_password, new_primary)
        
        # Verify old primary fails to unlock
        with self.assertRaises(ValueError):
            vault.unlock_vault(primary_password)
            
        # Verify new primary unlocks vault and decrypts successfully
        fernet_new = vault.unlock_vault(new_primary)
        self.assertIsNotNone(fernet_new)
        self.assertEqual(vault.get_entry(fernet_new, "facebook.com")[0]["password"], "fbpassword")

    def test_activity_logs(self):
        """Test that activities are recorded in activity_log."""
        password = "masterpassword123"
        vault.init_vault(password)
        fernet = vault.unlock_vault(password)
        
        vault.add_entry(fernet, "netflix.com", "netflixuser", "netflixpass")
        vault.get_entry(fernet, "netflix.com")
        vault.delete_entry("netflix.com")
        
        logs = vault.get_activity_logs()
        self.assertTrue(len(logs) >= 5)
        
        # Actions should be present in order (newest first)
        actions = [log["action"] for log in logs]
        self.assertIn("Entry Deleted", actions)
        self.assertIn("Entry Decrypted", actions)
        self.assertIn("Entry Created", actions)
        self.assertIn("Vault Unlocked", actions)
        self.assertIn("Vault Created", actions)

    def test_legacy_migration(self):
        """Test that a legacy database (no DEK) is migrated automatically on unlock."""
        password = "master_secret_123"
        # 1. Create a legacy database manually
        # Init SQLite tables in the old format (meta with salt and verifier only, entries without strength_score)
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            CREATE TABLE meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt BLOB NOT NULL,
                verifier BLOB NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                username TEXT,
                encrypted_password BLOB NOT NULL,
                notes TEXT,
                UNIQUE(site, username)
            )
            """
        )
        # 2. Derive key using the old way
        salt = os.urandom(16)
        key = vault._derive_key(password, salt)
        fernet = vault.Fernet(key)
        verifier = fernet.encrypt(vault.VERIFIER_TEXT)
        conn.execute("INSERT INTO meta (id, salt, verifier) VALUES (1, ?, ?)", (salt, verifier))
        
        # 3. Add an entry encrypted with the master key directly (legacy way)
        legacy_enc_pwd = fernet.encrypt(b"secret123")
        conn.execute(
            "INSERT INTO entries (site, username, encrypted_password, notes) VALUES (?, ?, ?, ?)",
            ("github.com", "user1", legacy_enc_pwd, "legacy notes")
        )
        conn.commit()
        conn.close()
        
        # 4. Now call unlock_vault. It should trigger the schema migration and DEK migration.
        fernet_dek = vault.unlock_vault(password)
        self.assertIsNotNone(fernet_dek)
        
        # 5. Check that metadata now has the DEK column populated
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT encrypted_dek_primary FROM meta WHERE id = 1").fetchone()
        self.assertIsNotNone(row[0]) # Should be migrated!
        
        # 6. Verify entry was re-encrypted and strength_score is backfilled
        row_entry = conn.execute("SELECT encrypted_password, strength_score FROM entries WHERE site='github.com'").fetchone()
        conn.close()
        self.assertIsNotNone(row_entry[1]) # strength_score should be populated!
        
        # Decrypt entry using DEK (fernet_dek)
        decrypted = fernet_dek.decrypt(row_entry[0]).decode("utf-8")
        self.assertEqual(decrypted, "secret123")

if __name__ == "__main__":
    unittest.main()
