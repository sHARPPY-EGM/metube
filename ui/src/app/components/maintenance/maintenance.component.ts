import { Component, inject, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../services/auth.service';
import { interval, Subscription } from 'rxjs';

@Component({
  selector: 'app-maintenance',
  imports: [CommonModule],
  templateUrl: './maintenance.component.html',
  styleUrl: './maintenance.component.sass'
})
export class MaintenanceComponent implements OnInit, OnDestroy {
  private authService = inject(AuthService);
  
  maintenanceMode = true;
  maintenanceUntil: string | null = null;
  countdown: string = '';
  showUnknown = false;
  private countdownSubscription: Subscription | null = null;
  private maintenanceCheckSubscription: Subscription | null = null;

  ngOnInit() {
    this.loadMaintenanceInfo();
    // Update countdown every second
    this.countdownSubscription = interval(1000).subscribe(() => {
      this.updateCountdown();
    });
    
    // Check if maintenance mode is still active every 2 seconds
    this.maintenanceCheckSubscription = interval(2000).subscribe(() => {
      this.checkMaintenanceMode();
    });
  }

  ngOnDestroy() {
    if (this.countdownSubscription) {
      this.countdownSubscription.unsubscribe();
    }
    if (this.maintenanceCheckSubscription) {
      this.maintenanceCheckSubscription.unsubscribe();
    }
  }

  checkMaintenanceMode() {
    this.authService.getMaintenanceInfo().subscribe(info => {
      // If maintenance mode is disabled, redirect to main page
      if (!info.maintenance_mode) {
        // Redirect to main page
        window.location.href = '/';
      }
    });
  }

  loadMaintenanceInfo() {
    this.authService.getMaintenanceInfo().subscribe(info => {
      this.maintenanceMode = info.maintenance_mode;
      this.maintenanceUntil = info.maintenance_until;
      this.updateCountdown();
    });
  }

  updateCountdown() {
    if (!this.maintenanceUntil) {
      this.countdown = '';
      this.showUnknown = true;
      return;
    }

    this.showUnknown = false;

    try {
      const until = new Date(this.maintenanceUntil);
      const now = new Date();
      const diff = until.getTime() - now.getTime();

      if (diff <= 0) {
        this.countdown = '';
        // Maintenance time expired, check if maintenance mode is still active
        this.checkMaintenanceMode();
        return;
      }

      const hours = Math.floor(diff / (1000 * 60 * 60));
      const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((diff % (1000 * 60)) / 1000);

      if (hours > 0) {
        this.countdown = `${hours}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
      } else {
        this.countdown = `${minutes}:${seconds.toString().padStart(2, '0')}`;
      }
    } catch (e) {
      this.countdown = '';
      this.showUnknown = true;
    }
  }
}

