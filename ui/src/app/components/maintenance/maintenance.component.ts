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
  
  maintenanceUntil: string | null = null;
  countdown: string = '';
  private countdownSubscription: Subscription | null = null;

  ngOnInit() {
    this.loadMaintenanceInfo();
    // Update countdown every second
    this.countdownSubscription = interval(1000).subscribe(() => {
      this.updateCountdown();
    });
  }

  ngOnDestroy() {
    if (this.countdownSubscription) {
      this.countdownSubscription.unsubscribe();
    }
  }

  loadMaintenanceInfo() {
    this.authService.getMaintenanceInfo().subscribe(info => {
      this.maintenanceUntil = info.maintenance_until;
      this.updateCountdown();
    });
  }

  updateCountdown() {
    if (!this.maintenanceUntil) {
      this.countdown = '';
      return;
    }

    try {
      const until = new Date(this.maintenanceUntil);
      const now = new Date();
      const diff = until.getTime() - now.getTime();

      if (diff <= 0) {
        this.countdown = '';
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
    }
  }
}

