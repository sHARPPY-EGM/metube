import { inject, Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { map, catchError } from 'rxjs/operators';

export interface AuthStatus {
  authenticated: boolean;
  password_required: boolean;
  has_site_password: boolean;
}

export interface AdminStatus {
  authenticated: boolean;
}

export interface AdminSettings {
  password_required: boolean;
  has_site_password: boolean;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private http = inject(HttpClient);

  isSetupNeeded(): Observable<boolean> {
    return this.http.get<{setup_needed: boolean}>('api/setup/status').pipe(
      map(response => response.setup_needed),
      catchError(() => of(true)) // Assume setup needed on error
    );
  }

  getAuthStatus(): Observable<AuthStatus> {
    return this.http.get<AuthStatus>('api/auth/status').pipe(
      catchError(() => of({
        authenticated: false,
        password_required: false,
        has_site_password: false
      }))
    );
  }

  login(password: string): Observable<{status: string} | {error: string}> {
    return this.http.post<{status: string} | {error: string}>('api/login', { password });
  }

  isAdminAuthenticated(): Observable<boolean> {
    return this.http.get<AdminStatus>('api/admin/status').pipe(
      map(response => response.authenticated),
      catchError(() => of(false))
    );
  }

  adminLogin(username: string, password: string): Observable<{status: string} | {error: string}> {
    return this.http.post<{status: string} | {error: string}>('api/admin/login', { username, password });
  }

  adminLogout(): Observable<{status: string}> {
    return this.http.post<{status: string}>('api/admin/logout', {});
  }

  getAdminSettings(): Observable<AdminSettings> {
    return this.http.get<AdminSettings>('api/admin/settings').pipe(
      catchError(() => of({
        password_required: false,
        has_site_password: false
      }))
    );
  }

  updateAdminSettings(settings: {
    site_password?: string;
    password_required?: boolean;
    admin_password?: string;
  }): Observable<{status: string} | {error: string}> {
    return this.http.post<{status: string} | {error: string}>('api/admin/settings', settings);
  }

  createAdmin(username: string, password: string): Observable<{status: string} | {error: string}> {
    return this.http.post<{status: string} | {error: string}>('api/setup', { username, password });
  }
}

