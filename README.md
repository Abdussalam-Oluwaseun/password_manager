# Password Generator & Manager

A web-based password generator and encrypted password manager with a modern user interface.

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

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Installation

1. Clone or navigate to the project directory:
```bash
cd password_manager
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the Flask app:
```bash
python app.py
```

4. Open your browser and visit:
```
http://localhost:5000
```

5. Create a new vault by setting a master password, or unlock an existing vault.

## Usage

### Web Interface

The password manager is accessed through a browser-based interface. Once you start the app and visit `http://localhost:5000`, you'll see:

#### Landing Page
- **Create New Vault**: If no vault exists, enter and confirm a strong master password (8+ characters, 12+ recommended)
- **Unlock Vault**: If a vault exists, enter your master password to access it

#### Dashboard
Access after unlocking the vault. The dashboard has two main sections:

**Left Panel — Password Tools:**
- **Generate Password**: Configure length, character sets, and generate strong passwords
  - Real-time strength indicator
  - Copy to clipboard
  - Save directly to vault
- **Generate Passphrase**: Create memorable Diceware-style passphrases
  - Configurable word count and separator
  - Strength feedback
- **Check Strength**: Enter any password to see strength analysis and feedback

**Right Panel — Vault Manager:**
- **Add Entry**: Store a site/service, username, and password
  - Auto-generate password within the form
  - Add optional notes
- **List Entries**: View all saved entries (passwords not shown in list)
  - Click any entry to view details
- **View Entry**: See full details including password
  - Copy password to clipboard
  - Show/hide password
  - Delete entry
- **Delete Entry**: Remove entries with confirmation

#### Settings Page
Access via the Settings link in the navigation bar:
- **Change Master Password**: Re-encrypt all vault entries with a new master password
- **Export Vault**: Download an encrypted JSON backup of all entries
- **Session Info**: View current session status (auto-logout after 30 min inactivity)

## Project Structure

```
password_manager/
├── app.py                  # Flask web application and API routes
├── generator.py             # Secure password / passphrase generation
├── strength.py              # Password strength scoring
├── vault.py                 # Key derivation, encryption, SQLite storage
├── requirements.txt         # Python dependencies
├── README.md
├── templates/
│   ├── base.html            # Base template with navigation
│   ├── index.html           # Landing page (init/unlock forms)
│   ├── dashboard.html       # Main dashboard (generator + vault)
│   └── settings.html        # Settings (change password, export)
├── static/
│   ├── app.js               # Global JavaScript utilities and handlers
│   └── custom.css           # Custom CSS styling (Bootstrap enhancements)
└── vault.db                 # SQLite database (created on first init)
```

## Security

- **Master Password**: Never stored or logged. Set once on vault creation, verified on each unlock.
- **Session Management**: Master password stored in server-side session after unlock; auto-expires after 30 minutes of inactivity.
- **Encryption**: All passwords encrypted individually with Fernet (AES-128-CBC + HMAC-SHA256).
- **PBKDF2**: Key derivation uses 480,000 iterations of PBKDF2-HMAC-SHA256 (OWASP 2023 guidance).
- **Database**: Passwords never stored in plaintext; SQLite stores only encrypted blobs.
- **Export**: Vault export is encrypted JSON — requires master password to decrypt.
- **Change Master Password**: Re-encrypts all entries with new key; old password cannot decrypt vault.

**Important**: If you lose your master password, your vault **cannot** be recovered. There is no backdoor by design.

## Additional Features

- **Password Generator**: Configurable length, character sets, ambiguous character exclusion
- **Passphrase Generator**: Diceware-style memorable passphrases
- **Strength Checker**: Entropy estimation, common-password detection, sequence/repeat detection
- **Export Backup**: Download encrypted JSON for safekeeping
- **Change Master Password**: Re-encrypt all entries with new master password
- **Session Timeout**: Auto-logout after 30 minutes of inactivity for security

## Future Enhancements

- Add password rotation reminders
- Breach checking against Have I Been Pwned API
- HTTPS support for remote deployment
- Multi-user support with authentication
- Browser extensions for auto-fill
- Mobile app
- Two-factor authentication (2FA)
