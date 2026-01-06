import os
import json
import bcrypt
import logging
from pathlib import Path

log = logging.getLogger('auth')

class AuthManager:
    def __init__(self, state_dir):
        self.state_dir = state_dir
        self.auth_file = os.path.join(state_dir, 'auth.json')
        self._ensure_dir()
        self._load()

    def _ensure_dir(self):
        """Ensure the state directory exists."""
        Path(self.state_dir).mkdir(parents=True, exist_ok=True)
        # Set restrictive permissions (owner read/write only)
        try:
            os.chmod(self.state_dir, 0o700)
        except Exception as e:
            log.warning(f'Could not set permissions on state directory: {e}')

    def _load(self):
        """Load authentication data from file."""
        if os.path.exists(self.auth_file):
            try:
                with open(self.auth_file, 'r') as f:
                    self.data = json.load(f)
                # Set restrictive permissions on auth file
                try:
                    os.chmod(self.auth_file, 0o600)
                except Exception as e:
                    log.warning(f'Could not set permissions on auth file: {e}')
            except json.JSONDecodeError:
                log.error('Auth file is corrupted, resetting')
                self.data = {}
        else:
            self.data = {}
        self._ensure_structure()

    def _ensure_structure(self):
        """Ensure data structure has all required fields."""
        defaults = {
            'admin_username': None,  # Store username in plain text (only one admin)
            'admin_password_hash': None,
            'site_password_hash': None,
            'password_required': False,
            'maintenance_mode': False,
            'maintenance_until': None  # ISO timestamp string
        }
        # Migrate from old format if needed
        if 'admin_username_hash' in self.data and 'admin_username' not in self.data:
            # Old format - we can't recover the username, so set to None
            self.data['admin_username'] = None
        for key, default in defaults.items():
            if key not in self.data:
                self.data[key] = default

    def _save(self):
        """Save authentication data to file."""
        try:
            with open(self.auth_file, 'w') as f:
                json.dump(self.data, f)
            # Set restrictive permissions
            try:
                os.chmod(self.auth_file, 0o600)
            except Exception as e:
                log.warning(f'Could not set permissions on auth file: {e}')
        except Exception as e:
            log.error(f'Failed to save auth data: {e}')
            raise

    def _hash_password(self, password: str) -> str:
        """Hash a password using bcrypt."""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify a password against a hash."""
        if not password_hash:
            return False
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception as e:
            log.error(f'Password verification error: {e}')
            return False

    def is_setup_complete(self) -> bool:
        """Check if admin account has been created."""
        return self.data['admin_username'] is not None and self.data['admin_password_hash'] is not None

    def create_admin(self, username: str, password: str) -> bool:
        """Create the initial admin account."""
        if self.is_setup_complete():
            log.warning('Admin account already exists')
            return False
        
        if not username or not password:
            return False
        
        if len(password) < 8:
            return False
        
        self.data['admin_username'] = username.strip()
        self.data['admin_password_hash'] = self._hash_password(password)
        self._save()
        log.info('Admin account created successfully')
        return True

    def verify_admin(self, username: str, password: str) -> bool:
        """Verify admin credentials."""
        if not self.is_setup_complete():
            return False
        
        # Verify username matches (case-insensitive)
        stored_username = self.data.get('admin_username', '')
        if not stored_username or username.strip().lower() != stored_username.lower():
            return False
        
        # Verify password
        return self._verify_password(password, self.data['admin_password_hash'])

    def set_site_password(self, password: str) -> bool:
        """Set or update the site password."""
        if not password:
            # Clear the password
            self.data['site_password_hash'] = None
            self._save()
            return True
        
        if len(password) < 4:
            return False
        
        self.data['site_password_hash'] = self._hash_password(password)
        self._save()
        log.info('Site password updated')
        return True

    def verify_site_password(self, password: str) -> bool:
        """Verify site password."""
        if not self.data['site_password_hash']:
            return False
        return self._verify_password(password, self.data['site_password_hash'])

    def is_password_required(self) -> bool:
        """Check if site password is required."""
        return self.data['password_required']

    def set_password_required(self, required: bool):
        """Set whether site password is required."""
        self.data['password_required'] = required
        self._save()
        log.info(f'Password requirement set to {required}')

    def has_site_password(self) -> bool:
        """Check if site password is set."""
        return self.data.get('site_password_hash') is not None

    def change_admin_password(self, old_password: str, new_password: str) -> bool:
        """Change admin password (requires verification of old password)."""
        if not self.is_setup_complete():
            return False
        
        # Verify old password
        if not self._verify_password(old_password, self.data['admin_password_hash']):
            log.warning('Failed to change admin password: old password incorrect')
            return False
        
        if len(new_password) < 8:
            return False
        
        self.data['admin_password_hash'] = self._hash_password(new_password)
        self._save()
        log.info('Admin password changed successfully')
        return True

    def get_status(self) -> dict:
        """Get current authentication status."""
        return {
            'setup_complete': self.is_setup_complete(),
            'password_required': self.is_password_required(),
            'has_site_password': self.data['site_password_hash'] is not None
        }
    
    def is_maintenance_mode(self) -> bool:
        """Check if maintenance mode is active."""
        if not self.data.get('maintenance_mode', False):
            return False
        
        # Check if maintenance_until is set and has expired
        maintenance_until = self.data.get('maintenance_until')
        if maintenance_until:
            try:
                from datetime import datetime
                until_dt = datetime.fromisoformat(maintenance_until)
                if datetime.now() >= until_dt:
                    # Maintenance period expired, disable maintenance mode
                    self.data['maintenance_mode'] = False
                    self.data['maintenance_until'] = None
                    self._save()
                    log.info('Maintenance mode expired, automatically disabled')
                    return False
            except (ValueError, TypeError) as e:
                log.warning(f'Invalid maintenance_until timestamp: {e}')
        
        return True
    
    def get_maintenance_until(self) -> str | None:
        """Get maintenance until timestamp."""
        return self.data.get('maintenance_until')
    
    def set_maintenance_mode(self, enabled: bool, until: str | None = None):
        """Enable or disable maintenance mode."""
        self.data['maintenance_mode'] = enabled
        self.data['maintenance_until'] = until
        self._save()
        log.info(f'Maintenance mode set to {enabled}' + (f' until {until}' if until else ''))

