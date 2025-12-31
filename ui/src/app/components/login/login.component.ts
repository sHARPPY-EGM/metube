import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-login',
  imports: [FormsModule, CommonModule],
  templateUrl: './login.component.html',
  styleUrl: './login.component.sass'
})
export class LoginComponent {
  private authService = inject(AuthService);
  
  password = '';
  error = '';
  loading = false;

  onSubmit() {
    this.error = '';
    
    if (!this.password) {
      this.error = 'Passwort ist erforderlich';
      return;
    }
    
    this.loading = true;
    this.authService.login(this.password).subscribe({
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
        this.error = 'Fehler beim Anmelden';
        this.loading = false;
      }
    });
  }
}

