import { inject, Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { map, catchError } from 'rxjs/operators';

export interface AuthStatus {
  setup_needed: boolean;
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
  maintenance_mode?: boolean;
  maintenance_until?: string | null;
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
        setup_needed: true,
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
        has_site_password: false,
        maintenance_mode: false,
        maintenance_until: null
      }))
    );
  }

  updateAdminSettings(settings: {
    site_password?: string;
    password_required?: boolean;
    admin_password?: string;
    maintenance_mode?: boolean;
    maintenance_until?: string | null;
  }): Observable<{status: string} | {error: string}> {
    return this.http.post<{status: string} | {error: string}>('api/admin/settings', settings);
  }
  
  getMaintenanceInfo(): Observable<{maintenance_mode: boolean; maintenance_until: string | null}> {
    return this.http.get<{maintenance_mode: boolean; maintenance_until: string | null}>('api/maintenance').pipe(
      catchError(() => of({
        maintenance_mode: false,
        maintenance_until: null
      }))
    );
  }

  createAdmin(username: string, password: string): Observable<{status: string} | {error: string}> {
    return this.http.post<{status: string} | {error: string}>('api/setup', { username, password });
  }
}

