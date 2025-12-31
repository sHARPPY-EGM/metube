import { Component, inject, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import { faCog, faLock, faUnlock, faEye, faEyeSlash } from '@fortawesome/free-solid-svg-icons';
import { AuthService, AdminSettings } from '../../services/auth.service';

@Component({
  selector: 'app-admin',
  imports: [FormsModule, CommonModule, FontAwesomeModule],
  templateUrl: './admin.component.html',
  styleUrl: './admin.component.sass'
})
export class AdminComponent implements OnInit {
  private authService = inject(AuthService);
  
  // Icons
  faCog = faCog;
  faLock = faLock;
  faUnlock = faUnlock;
  faEye = faEye;
  faEyeSlash = faEyeSlash;
  
  // Admin login
  adminUsername = '';
  adminPassword = '';
  adminLoginError = '';
  adminLoginLoading = false;
  isAdminAuthenticated = false;
  
  // Settings
  settings: AdminSettings = {
    password_required: false,
    has_site_password: false
  };
  
  // Site password
  sitePassword = '';
  sitePasswordConfirm = '';
  sitePasswordError = '';
  sitePasswordLoading = false;
  showSitePassword = false;
  
  // Admin password change
  adminPasswordNew = '';
  adminPasswordNewConfirm = '';
  adminPasswordError = '';
  adminPasswordLoading = false;
  showAdminPassword = false;
  
  ngOnInit() {
    this.checkAdminAuth();
    this.loadSettings();
  }
  
  checkAdminAuth() {
    this.authService.isAdminAuthenticated().subscribe(authenticated => {
      this.isAdminAuthenticated = authenticated;
      if (authenticated) {
        this.loadSettings();
      }
    });
  }
  
  loadSettings() {
    if (!this.isAdminAuthenticated) return;
    
    this.authService.getAdminSettings().subscribe(settings => {
      this.settings = settings;
    });
  }
  
  onAdminLogin() {
    this.adminLoginError = '';
    
    if (!this.adminUsername.trim() || !this.adminPassword) {
      this.adminLoginError = 'Benutzername und Passwort sind erforderlich';
      return;
    }
    
    this.adminLoginLoading = true;
    this.authService.adminLogin(this.adminUsername.trim(), this.adminPassword).subscribe({
      next: (response) => {
        if ('error' in response) {
          this.adminLoginError = response.error;
          this.adminLoginLoading = false;
        } else {
          this.isAdminAuthenticated = true;
          this.adminPassword = '';
          this.loadSettings();
        }
      },
      error: () => {
        this.adminLoginError = 'Fehler beim Anmelden';
        this.adminLoginLoading = false;
      }
    });
  }
  
  onAdminLogout() {
    this.authService.adminLogout().subscribe(() => {
      this.isAdminAuthenticated = false;
      this.adminUsername = '';
      this.adminPassword = '';
      this.settings = {
        password_required: false,
        has_site_password: false
      };
    });
  }
  
  togglePasswordRequired() {
    if (!this.isAdminAuthenticated) return;
    
    const newValue = !this.settings.password_required;
    this.authService.updateAdminSettings({ password_required: newValue }).subscribe({
      next: (response) => {
        if ('error' in response) {
          alert('Fehler beim Aktualisieren: ' + response.error);
        } else {
          this.settings.password_required = newValue;
        }
      },
      error: () => {
        alert('Fehler beim Aktualisieren der Einstellungen');
      }
    });
  }
  
  onSetSitePassword() {
    this.sitePasswordError = '';
    
    if (!this.sitePassword) {
      // Clear password
      this.sitePasswordLoading = true;
      this.authService.updateAdminSettings({ site_password: '' }).subscribe({
        next: (response) => {
          if ('error' in response) {
            this.sitePasswordError = response.error;
          } else {
            this.sitePassword = '';
            this.sitePasswordConfirm = '';
            this.loadSettings();
          }
          this.sitePasswordLoading = false;
        },
        error: () => {
          this.sitePasswordError = 'Fehler beim Aktualisieren';
          this.sitePasswordLoading = false;
        }
      });
      return;
    }
    
    if (this.sitePassword.length < 4) {
      this.sitePasswordError = 'Passwort muss mindestens 4 Zeichen lang sein';
      return;
    }
    
    if (this.sitePassword !== this.sitePasswordConfirm) {
      this.sitePasswordError = 'Passwörter stimmen nicht überein';
      return;
    }
    
    this.sitePasswordLoading = true;
    this.authService.updateAdminSettings({ site_password: this.sitePassword }).subscribe({
      next: (response) => {
        if ('error' in response) {
          this.sitePasswordError = response.error;
        } else {
          this.sitePassword = '';
          this.sitePasswordConfirm = '';
          this.loadSettings();
        }
        this.sitePasswordLoading = false;
      },
      error: () => {
        this.sitePasswordError = 'Fehler beim Setzen des Passworts';
        this.sitePasswordLoading = false;
      }
    });
  }
  
  onChangeAdminPassword() {
    this.adminPasswordError = '';
    
    if (!this.adminPasswordNew) {
      this.adminPasswordError = 'Passwort ist erforderlich';
      return;
    }
    
    if (this.adminPasswordNew.length < 8) {
      this.adminPasswordError = 'Passwort muss mindestens 8 Zeichen lang sein';
      return;
    }
    
    if (this.adminPasswordNew !== this.adminPasswordNewConfirm) {
      this.adminPasswordError = 'Passwörter stimmen nicht überein';
      return;
    }
    
    this.adminPasswordLoading = true;
    this.authService.updateAdminSettings({ admin_password: this.adminPasswordNew }).subscribe({
      next: (response) => {
        if ('error' in response) {
          this.adminPasswordError = response.error;
        } else {
          this.adminPasswordNew = '';
          this.adminPasswordNewConfirm = '';
          alert('Admin-Passwort wurde erfolgreich geändert');
        }
        this.adminPasswordLoading = false;
      },
      error: () => {
        this.adminPasswordError = 'Fehler beim Ändern des Passworts';
        this.adminPasswordLoading = false;
      }
    });
  }
}

