import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-setup',
  imports: [FormsModule, CommonModule],
  templateUrl: './setup.component.html',
  styleUrl: './setup.component.sass'
})
export class SetupComponent {
  private authService = inject(AuthService);
  
  username = '';
  password = '';
  confirmPassword = '';
  error = '';
  loading = false;

  onSubmit() {
    this.error = '';
    
    if (!this.username.trim()) {
      this.error = 'Benutzername ist erforderlich';
      return;
    }
    
    if (!this.password) {
      this.error = 'Passwort ist erforderlich';
      return;
    }
    
    if (this.password.length < 8) {
      this.error = 'Passwort muss mindestens 8 Zeichen lang sein';
      return;
    }
    
    if (this.password !== this.confirmPassword) {
      this.error = 'Passwörter stimmen nicht überein';
      return;
    }
    
    this.loading = true;
    this.authService.createAdmin(this.username.trim(), this.password).subscribe({
      next: (response) => {
        if ('error' in response) {
          this.error = response.error;
          this.loading = false;
        } else {
          // Redirect to main page
          window.location.href = '/';
        }
      },
      error: (err) => {
        this.error = 'Fehler beim Erstellen des Admin-Accounts';
        this.loading = false;
      }
    });
  }
}

