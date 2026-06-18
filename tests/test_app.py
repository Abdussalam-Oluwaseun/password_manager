import unittest
import os
import json
import tempfile
import io
import vault
from app import app

class TestApp(unittest.TestCase):
    def setUp(self):
        """Set up Flask test client and isolated SQLite database."""
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.db_fd)
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

        self.original_db_path = vault.DB_PATH
        vault.DB_PATH = self.db_path
        
        # Configure app for testing
        app.config["TESTING"] = True
        # Keep secret key stable/simple for test sessions
        app.config["SECRET_KEY"] = "test-secret-key"
        self.app = app
        self.client = self.app.test_client()

    def tearDown(self):
        """Restore DB path and delete the temporary database file."""
        vault.DB_PATH = self.original_db_path
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except OSError:
                pass

    def test_index_uninitialized_vault(self):
        """Test index page returns status indicating vault does not exist."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        # Verify landing page templates indicators
        self.assertIn(b"Create New Vault", response.data or b"")

    def test_api_init_success(self):
        """Test successful vault initialization through API."""
        response = self.client.post(
            "/api/init",
            data=json.dumps({
                "master_password": "supersecurepassword123",
                "confirm_password": "supersecurepassword123"
            }),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertIn("Vault created successfully", data.get("message", ""))

    def test_api_init_validation(self):
        """Test password validation on init."""
        # Non-matching passwords
        response = self.client.post(
            "/api/init",
            data=json.dumps({
                "master_password": "pwd1",
                "confirm_password": "pwd2"
            }),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        
        # Short password warning
        response = self.client.post(
            "/api/init",
            data=json.dumps({
                "master_password": "short",
                "confirm_password": "short"
            }),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertIn("Warning", data.get("warning", ""))

    def test_api_unlock_success_and_failure(self):
        """Test unlocking vault API."""
        # Initialize first
        vault.init_vault("masterpass")

        # Wrong password
        response = self.client.post(
            "/api/unlock",
            data=json.dumps({"master_password": "wrong"}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 401)

        # Correct password
        response = self.client.post(
            "/api/unlock",
            data=json.dumps({"master_password": "masterpass"}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)

    def test_unauthenticated_api_endpoints_return_401(self):
        """Test that vault APIs return 401 unauthorized when session is not active."""
        endpoints = [
            ("/api/vault/list", "GET", None),
            ("/api/vault/add", "POST", {}),
            ("/api/vault/get/mysite", "GET", None),
            ("/api/vault/delete/mysite", "DELETE", {}),
            ("/api/vault/export", "GET", None),
            ("/api/settings/change-password", "POST", {}),
        ]
        
        for url, method, body in endpoints:
            if method == "GET":
                response = self.client.get(url)
            elif method == "POST":
                response = self.client.post(url, data=json.dumps(body), content_type="application/json")
            elif method == "DELETE":
                response = self.client.delete(url, data=json.dumps(body), content_type="application/json")
            self.assertEqual(response.status_code, 401, f"{method} {url} did not return 401")

    def test_authenticated_vault_flow(self):
        """Test CRUD, export, and settings changes with an active session."""
        password = "masterpassword123"
        # 1. Initialize and login (cookie will be stored automatically in test client)
        self.client.post(
            "/api/init",
            data=json.dumps({
                "master_password": password,
                "confirm_password": password
            }),
            content_type="application/json"
        )

        # 2. Add an entry
        add_res = self.client.post(
            "/api/vault/add",
            data=json.dumps({
                "site": "facebook.com",
                "username": "fbuser",
                "password": "fbpassword1!",
                "notes": "my fb"
            }),
            content_type="application/json"
        )
        self.assertEqual(add_res.status_code, 201)

        # 3. List entries
        list_res = self.client.get("/api/vault/list")
        self.assertEqual(list_res.status_code, 200)
        list_data = json.loads(list_res.data)
        self.assertEqual(len(list_data["entries"]), 1)
        self.assertEqual(list_data["entries"][0]["site"], "facebook.com")
        self.assertNotIn("password", list_data["entries"][0]) # Password shouldn't be listed

        # 4. Get decrypted password
        get_res = self.client.get("/api/vault/get/facebook.com")
        self.assertEqual(get_res.status_code, 200)
        get_data = json.loads(get_res.data)
        self.assertEqual(len(get_data["entries"]), 1)
        self.assertEqual(get_data["entries"][0]["password"], "fbpassword1!")

        # 5. Export entries
        export_res = self.client.get("/api/vault/export")
        self.assertEqual(export_res.status_code, 200)
        self.assertEqual(export_res.mimetype, "application/json")
        export_data = json.loads(export_res.data)
        self.assertEqual(len(export_data), 1)
        self.assertEqual(export_data[0]["site"], "facebook.com")
        self.assertEqual(export_data[0]["password"], "fbpassword1!")

        # 6. Change master password
        new_password = "newmasterpassword456"
        change_res = self.client.post(
            "/api/settings/change-password",
            data=json.dumps({
                "old_password": password,
                "new_password": new_password,
                "confirm_password": new_password
            }),
            content_type="application/json"
        )
        self.assertEqual(change_res.status_code, 200)

        # 7. Check we can still fetch after password update (session updated)
        get_res_after = self.client.get("/api/vault/get/facebook.com")
        self.assertEqual(get_res_after.status_code, 200)

        # 8. Delete entry
        del_res = self.client.delete(
            "/api/vault/delete/facebook.com",
            data=json.dumps({}),
            content_type="application/json"
        )
        self.assertEqual(del_res.status_code, 200)
        self.assertEqual(len(vault.list_entries()), 0)

    def test_password_utilities_endpoints(self):
        """Test public endpoints for generating and checking passwords."""
        # 1. Generate password
        gen_res = self.client.get("/api/password/generate?length=20&use_symbols=true")
        self.assertEqual(gen_res.status_code, 200)
        gen_data = json.loads(gen_res.data)
        self.assertEqual(len(gen_data["password"]), 20)
        self.assertIn("strength", gen_data)

        # 2. Passphrase generation
        phrase_res = self.client.get("/api/password/passphrase?num_words=5&separator=_")
        self.assertEqual(phrase_res.status_code, 200)
        phrase_data = json.loads(phrase_res.data)
        self.assertEqual(len(phrase_data["passphrase"].split("_")), 5)

        # 3. Check strength
        check_res = self.client.post(
            "/api/password/check",
            data=json.dumps({"password": "Short"}),
            content_type="application/json"
        )
        self.assertEqual(check_res.status_code, 200)
        check_data = json.loads(check_res.data)
        self.assertIn("Too short", "".join(check_data["feedback"]))

    def test_recovery_endpoints(self):
        """Test the setting of a recovery password, unlocking with it, and resetting primary master."""
        primary_pw = "primary123pwd"
        recovery_pw = "recovery999pwd"
        new_primary = "newprimary888pwd"
        
        # 1. Init vault and primary session
        init_res = self.client.post(
            "/api/init",
            data=json.dumps({
                "master_password": primary_pw,
                "confirm_password": primary_pw
            }),
            content_type="application/json"
        )
        self.assertEqual(init_res.status_code, 201)
        
        # 2. Configure recovery password
        set_rec_res = self.client.post(
            "/api/settings/set-recovery-password",
            data=json.dumps({
                "master_password": primary_pw,
                "recovery_password": recovery_pw,
                "confirm_recovery": recovery_pw
            }),
            content_type="application/json"
        )
        self.assertEqual(set_rec_res.status_code, 200)
        
        # 3. Log out primary session
        self.client.post("/api/logout")
        
        # 4. Try unlocking via recovery password
        unlock_rec_res = self.client.post(
            "/api/unlock",
            data=json.dumps({
                "master_password": recovery_pw,
                "use_recovery": True
            }),
            content_type="application/json"
        )
        self.assertEqual(unlock_rec_res.status_code, 200)
        
        # 5. Reset primary master password using recovery password
        reset_res = self.client.post(
            "/api/settings/reset-primary",
            data=json.dumps({
                "recovery_password": recovery_pw,
                "new_password": new_primary,
                "confirm_password": new_primary
            }),
            content_type="application/json"
        )
        self.assertEqual(reset_res.status_code, 200)
        
        # 6. Log out
        self.client.post("/api/logout")
        
        # 7. Verify we can log in with new primary master password
        unlock_new_res = self.client.post(
            "/api/unlock",
            data=json.dumps({
                "master_password": new_primary,
                "use_recovery": False
            }),
            content_type="application/json"
        )
        self.assertEqual(unlock_new_res.status_code, 200)

    def test_activity_log_endpoint(self):
        """Test getting activity logs list from route."""
        # Init
        self.client.post(
            "/api/init",
            data=json.dumps({
                "master_password": "mypassword123",
                "confirm_password": "mypassword123"
            }),
            content_type="application/json"
        )
        
        # List activity
        act_res = self.client.get("/api/activity/list")
        self.assertEqual(act_res.status_code, 200)
        act_data = json.loads(act_res.data)
        self.assertTrue(len(act_data["logs"]) > 0)
        self.assertEqual(act_data["logs"][0]["action"], "Vault Created")

if __name__ == "__main__":
    unittest.main()
