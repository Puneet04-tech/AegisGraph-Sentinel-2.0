import os
import time
import shutil
import logging
from datetime import datetime, timedelta
from typing import Optional
from src.observability.alert_manager import AlertManager
from src.observability.models import AlertSeverity
import threading

logger = logging.getLogger(__name__)

class DatabaseBackupManager:
    """
    Manages automated daily database backups, encryption, and retention policy.
    """
    def __init__(self, backup_dir: str = "backups", retention_days: int = 7):
        self.backup_dir = backup_dir
        self.retention_days = retention_days
        self.alert_manager = AlertManager()
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def trigger_backup(self) -> Optional[str]:
        """Triggers a full database backup and simulates encryption."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(self.backup_dir, f"backup_{timestamp}.enc")
        
        try:
            logger.info("Starting database backup process...")
            
            # Simulated dump & encryption for Neo4j/Postgres
            with open(backup_file, "w") as f:
                f.write(f"ENCRYPTED_DATABASE_DUMP_DATA_{timestamp}")
            
            logger.info(f"Backup completed successfully: {backup_file}")
            return backup_file
            
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            self.alert_manager.create_alert(
                title="Database Backup Failed",
                description=f"Automated backup failed with error: {str(e)}",
                severity=AlertSeverity.CRITICAL,
                component="BackupManager"
            )
            return None

    def clean_stale_backups(self):
        """Deletes backups older than retention_days."""
        cutoff_date = datetime.now() - timedelta(days=self.retention_days)
        try:
            for filename in os.listdir(self.backup_dir):
                filepath = os.path.join(self.backup_dir, filename)
                if os.path.isfile(filepath):
                    file_mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                    if file_mtime < cutoff_date:
                        os.remove(filepath)
                        logger.info(f"Deleted stale backup: {filename}")
        except Exception as e:
            logger.error(f"Failed to clean stale backups: {e}")
            self.alert_manager.create_alert(
                title="Backup Cleanup Failed",
                description=f"Failed to delete stale backups: {str(e)}",
                severity=AlertSeverity.HIGH,
                component="BackupManager"
            )

    def run_daily_worker(self):
        """Background worker that runs daily backup and cleanup."""
        logger.info("Daily backup background worker started.")
        while True:
            self.trigger_backup()
            self.clean_stale_backups()
            # Sleep for 24 hours
            time.sleep(86400)
            
def start_backup_daemon():
    manager = DatabaseBackupManager()
    thread = threading.Thread(target=manager.run_daily_worker, daemon=True)
    thread.start()
    return thread

if __name__ == "__main__":
    manager = DatabaseBackupManager()
    manager.trigger_backup()
    manager.clean_stale_backups()
