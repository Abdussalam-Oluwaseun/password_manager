#!/usr/bin/env python3
"""
app.py
Flask web application for the password manager.

Provides RESTful API routes for vault management, password generation,
and settings. Uses server-side sessions for authentication.
"""

import json
import os
from functools import wraps
from datetime import timedelta

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from hmac import compare_digest as safe_str_cmp

import vault
import generator
import strength


# ============================================================================
# Flask App Configuration
# ============================================================================

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.urandom(32).hex()  # Generate random secret key
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True


# ============================================================================
# Authentication & Session Helpers
# ============================================================================

def require_session(f):
    """Decorator to require an active, authenticated session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'master_password' not in session:
            return jsonify({'error': 'Not authenticated. Please unlock the vault first.'}), 401
        return f(*args, **kwargs)
    return decorated_function


def get_master_password_from_session():
    """Retrieve the master password from session."""
    return session.get('master_password')


def get_fernet_from_session():
    """Unlock vault with session master password and return Fernet object."""
    master_password = get_master_password_from_session()
    if not master_password:
        raise ValueError("Session expired or not authenticated.")
    try:
        use_recovery = session.get('use_recovery', False)
        return vault.unlock_vault(master_password, use_recovery=use_recovery)
    except ValueError as e:
        raise ValueError(f"Failed to unlock vault: {e}")


# ============================================================================
# Routes: Landing & Authentication
# ============================================================================

@app.route('/')
def index():
    """Landing page: check vault status and redirect or render forms."""
    if 'master_password' in session:
        return redirect(url_for('dashboard'))
    
    vault_exists = vault.vault_exists()
    return render_template('index.html', vault_exists=vault_exists)


@app.route('/api/init', methods=['POST'])
def api_init():
    """Initialize a new vault with master password."""
    if vault.vault_exists():
        return jsonify({'error': 'Vault already exists.'}), 400
    
    data = request.get_json() or {}
    master_password = data.get('master_password', '').strip()
    confirm_password = data.get('confirm_password', '').strip()
    
    if not master_password:
        return jsonify({'error': 'Master password is required.'}), 400
    
    if master_password != confirm_password:
        return jsonify({'error': 'Passwords do not match.'}), 400
    
    if len(master_password) < 8:
        return jsonify({'warning': 'Warning: Master password is short. Consider using 12+ characters.'}), 201
    
    try:
        vault.init_vault(master_password)
        session['master_password'] = master_password
        session.permanent = True
        return jsonify({'message': 'Vault created successfully.'}), 201
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/unlock', methods=['POST'])
def api_unlock():
    """Unlock vault with master password and start session."""
    if 'master_password' in session:
        return jsonify({'message': 'Vault already unlocked.'}), 200
    
    data = request.get_json() or {}
    master_password = data.get('master_password', '').strip()
    use_recovery = data.get('use_recovery', False)
    
    if not master_password:
        return jsonify({'error': 'Master password is required.'}), 400
    
    try:
        vault.unlock_vault(master_password, use_recovery=use_recovery)
        session['master_password'] = master_password
        session['use_recovery'] = use_recovery
        session.permanent = True
        return jsonify({'message': 'Vault unlocked successfully.'}), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 401


@app.route('/api/logout', methods=['POST'])
def api_logout():
    """Logout and clear session."""
    vault.add_activity_log("Vault Locked", "User logged out / session ended")
    session.clear()
    return jsonify({'message': 'Logged out successfully.'}), 200


@app.route('/dashboard')
def dashboard():
    """Main dashboard page (requires authentication)."""
    if 'master_password' not in session:
        return redirect(url_for('index'))
    return render_template('dashboard.html')


@app.route('/vault')
def vault_page():
    """Vault page (requires authentication)."""
    if 'master_password' not in session:
        return redirect(url_for('index'))
    return render_template('vault.html')


@app.route('/generator')
def generator_page():
    """Generator & Analyzer page (requires authentication)."""
    if 'master_password' not in session:
        return redirect(url_for('index'))
    return render_template('generator.html')


# ============================================================================
# Routes: Vault Management
# ============================================================================

@app.route('/api/vault/list', methods=['GET'])
@require_session
def api_vault_list():
    """List all vault entries (without passwords)."""
    try:
        entries = vault.list_entries()
        return jsonify({'entries': entries}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/vault/add', methods=['POST'])
@require_session
def api_vault_add():
    """Add a new entry to the vault."""
    data = request.get_json() or {}
    site = data.get('site', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    notes = data.get('notes', '').strip()
    
    if not site or not username or not password:
        return jsonify({'error': 'Site, username, and password are required.'}), 400
    
    try:
        fernet = get_fernet_from_session()
        vault.add_entry(fernet, site, username, password, notes=notes)
        return jsonify({'message': 'Entry added successfully.'}), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/vault/get/<site>', methods=['GET'])
@require_session
def api_vault_get(site):
    """Retrieve entries for a specific site."""
    try:
        fernet = get_fernet_from_session()
        entries = vault.get_entry(fernet, site)
        if not entries:
            return jsonify({'error': f"No entries found for '{site}'."}), 404
        return jsonify({'entries': entries}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/vault/delete/<site>', methods=['DELETE'])
@require_session
def api_vault_delete(site):
    """Delete entries for a specific site."""
    data = request.get_json() or {}
    username = data.get('username')  # Optional: if provided, delete specific username entry
    
    try:
        deleted = vault.delete_entry(site, username=username)
        if deleted == 0:
            return jsonify({'error': f"No entries found for '{site}'."}), 404
        return jsonify({'message': f'Deleted {deleted} entry(ies).'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/vault/export', methods=['GET'])
@require_session
def api_vault_export():
    """Export vault entries as encrypted JSON backup."""
    try:
        fernet = get_fernet_from_session()
        entries = vault.list_entries()
        
        # Decrypt and include passwords in export
        export_data = []
        for entry_base in entries:
            site = entry_base['site']
            entries_for_site = vault.get_entry(fernet, site)
            export_data.extend(entries_for_site)
        
        # Create JSON export
        export_json = json.dumps(export_data, indent=2, default=str)
        
        # Return as downloadable file
        import io
        return send_file(
            io.BytesIO(export_json.encode('utf-8')),
            mimetype='application/json',
            as_attachment=True,
            download_name='vault_backup.json'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Routes: Settings
# ============================================================================

@app.route('/settings')
def settings_page():
    """Settings page (requires authentication)."""
    if 'master_password' not in session:
        return redirect(url_for('index'))
    return render_template('settings.html')


@app.route('/api/settings/change-password', methods=['POST'])
@require_session
def api_change_password():
    """Change master password and re-encrypt all entries."""
    data = request.get_json() or {}
    old_password = data.get('old_password', '').strip()
    new_password = data.get('new_password', '').strip()
    confirm_password = data.get('confirm_password', '').strip()
    
    if not old_password or not new_password:
        return jsonify({'error': 'Both old and new passwords are required.'}), 400
    
    if new_password != confirm_password:
        return jsonify({'error': 'New passwords do not match.'}), 400
    
    if len(new_password) < 8:
        return jsonify({'warning': 'Warning: Master password is short. Consider using 12+ characters.'}), 201
    
    try:
        # Verify old password matches current session
        if not safe_str_cmp(old_password, get_master_password_from_session()):
            return jsonify({'error': 'Current master password is incorrect.'}), 401
        
        # Update master password (re-encrypts all entries)
        vault.update_master_password(old_password, new_password)
        
        # Update session with new master password
        session['master_password'] = new_password
        
        return jsonify({'message': 'Master password changed successfully.'}), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/settings/set-recovery-password', methods=['POST'])
@require_session
def api_set_recovery_password():
    """Establish secondary master/recovery password."""
    data = request.get_json() or {}
    master_password = data.get('master_password', '').strip()
    recovery_password = data.get('recovery_password', '').strip()
    confirm_recovery = data.get('confirm_recovery', '').strip()
    
    if not master_password or not recovery_password or not confirm_recovery:
        return jsonify({'error': 'Master password, recovery password, and confirmation are required.'}), 400
         
    if recovery_password != confirm_recovery:
        return jsonify({'error': 'Recovery passwords do not match.'}), 400
         
    if len(recovery_password) < 8:
        return jsonify({'error': 'Recovery password must be at least 8 characters long.'}), 400
         
    try:
        if not safe_str_cmp(master_password, get_master_password_from_session()):
            return jsonify({'error': 'Current master password is incorrect.'}), 401
            
        vault.set_secondary_password_with_primary(master_password, recovery_password)
        return jsonify({'message': 'Recovery password configured successfully.'}), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/settings/reset-primary', methods=['POST'])
@require_session
def api_reset_primary():
    """Reset primary master password using recovery password."""
    if not session.get('use_recovery', False):
        return jsonify({'error': 'This operation requires unlocking the vault using the recovery password.'}), 403
         
    data = request.get_json() or {}
    recovery_password = data.get('recovery_password', '').strip()
    new_password = data.get('new_password', '').strip()
    confirm_password = data.get('confirm_password', '').strip()
    
    if not recovery_password or not new_password or not confirm_password:
        return jsonify({'error': 'Recovery password, new master password, and confirmation are required.'}), 400
         
    if new_password != confirm_password:
        return jsonify({'error': 'New passwords do not match.'}), 400
         
    if len(new_password) < 8:
        return jsonify({'error': 'New master password must be at least 8 characters long.'}), 400
         
    try:
        if not safe_str_cmp(recovery_password, get_master_password_from_session()):
            return jsonify({'error': 'Recovery password is incorrect.'}), 401
            
        vault.update_master_password_with_recovery(recovery_password, new_password)
        
        session['master_password'] = new_password
        session['use_recovery'] = False
        
        return jsonify({'message': 'Master password reset successfully. You are now switched back to a primary session.'}), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/activity/list', methods=['GET'])
@require_session
def api_activity_list():
    """Get list of recent user activities."""
    try:
        limit = int(request.args.get('limit', 50))
        logs = vault.get_activity_logs(limit=limit)
        return jsonify({'logs': logs}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Routes: Password Utilities
# ============================================================================

@app.route('/api/password/generate', methods=['GET'])
def api_password_generate():
    """Generate a random password."""
    try:
        length = int(request.args.get('length', 16))
        use_upper = request.args.get('use_upper', 'true').lower() == 'true'
        use_lower = request.args.get('use_lower', 'true').lower() == 'true'
        use_digits = request.args.get('use_digits', 'true').lower() == 'true'
        use_symbols = request.args.get('use_symbols', 'true').lower() == 'true'
        exclude_ambiguous = request.args.get('exclude_ambiguous', 'false').lower() == 'true'
        
        password = generator.generate_password(
            length=length,
            use_upper=use_upper,
            use_lower=use_lower,
            use_digits=use_digits,
            use_symbols=use_symbols,
            exclude_ambiguous=exclude_ambiguous,
        )
        
        strength_result = strength.check_strength(password)
        
        return jsonify({
            'password': password,
            'strength': strength_result,
        }), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/password/check', methods=['POST'])
def api_password_check():
    """Check password strength."""
    data = request.get_json() or {}
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password is required.'}), 400
    
    try:
        result = strength.check_strength(password)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/password/passphrase', methods=['GET'])
def api_password_passphrase():
    """Generate a passphrase."""
    try:
        num_words = int(request.args.get('num_words', 4))
        separator = request.args.get('separator', '-')
        
        passphrase = generator.generate_passphrase(num_words=num_words, separator=separator)
        strength_result = strength.check_strength(passphrase)
        
        return jsonify({
            'passphrase': passphrase,
            'strength': strength_result,
        }), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({'error': 'Not found.'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return jsonify({'error': 'Internal server error.'}), 500


# ============================================================================
# Main
# ============================================================================

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
