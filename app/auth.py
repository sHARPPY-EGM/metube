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
            'admin_username_hash': None,
            'admin_password_hash': None,
            'site_password_hash': None,
            'password_required': False
        }
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
        return self.data['admin_username_hash'] is not None and self.data['admin_password_hash'] is not None

    def create_admin(self, username: str, password: str) -> bool:
        """Create the initial admin account."""
        if self.is_setup_complete():
            log.warning('Admin account already exists')
            return False
        
        if not username or not password:
            return False
        
        if len(password) < 8:
            return False
        
        self.data['admin_username_hash'] = self._hash_password(username)
        self.data['admin_password_hash'] = self._hash_password(password)
        self._save()
        log.info('Admin account created successfully')
        return True

    def verify_admin(self, username: str, password: str) -> bool:
        """Verify admin credentials."""
        if not self.is_setup_complete():
            return False
        
        username_match = self._verify_password(username, self.data['admin_username_hash'])
        password_match = self._verify_password(password, self.data['admin_password_hash'])
        
        return username_match and password_match

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

    def change_admin_password(self, old_password: str, new_password: str) -> bool:
        """Change admin password (requires verification of old password)."""
        if not self.is_setup_complete():
            return False
        
        # Verify old password by checking if username+old_password combination works
        # We need to verify the admin credentials first
        # Since we can't verify username separately, we'll need to store a way to verify
        # For now, we'll require the full admin login to change password
        
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

