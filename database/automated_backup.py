import base64
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, unquote

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.observability.alert_manager import AlertManager
from src.observability.models import AlertSeverity

logger = logging.getLogger(__name__)


_BACKUP_MAGIC = b"AEGIS-BACKUP-1\n"
_AES_GCM_NONCE_SIZE = 12
_AES_GCM_KEY_SIZE = 32


class DatabaseBackupManager:
    """
    Manages automated daily database backups, encryption, and retention policy.
    """
    def __init__(
        self,
        backup_dir: str = "backups",
        retention_days: int = 7,
        *,
        database_url: Optional[str] = None,
        backup_encryption_key: Optional[str] = None,
        backup_tool_path: Optional[str] = None,
    ):
        self.backup_dir = backup_dir
        self.retention_days = retention_days
        self.database_url = database_url or os.getenv("BACKUP_DATABASE_URL") or os.getenv("DATABASE_URL")
        self.backup_tool_path = backup_tool_path or os.getenv("BACKUP_TOOL_PATH")
        self.backup_encryption_key = backup_encryption_key or os.getenv("BACKUP_ENCRYPTION_KEY")
        self.alert_manager = AlertManager()
        Path(self.backup_dir).mkdir(parents=True, exist_ok=True)
    
    def trigger_backup(self) -> Optional[str]:
        """Triggers a full database backup and encrypts the result."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = Path(self.backup_dir) / f"backup_{timestamp}.enc"
        dump_suffix = self._dump_suffix()
        dump_fd, dump_name = tempfile.mkstemp(prefix=f"backup_{timestamp}_", suffix=dump_suffix)
        os.close(dump_fd)
        dump_path = Path(dump_name)
        
        try:
            logger.info("Starting database backup process...")
            self._create_database_dump(dump_path)
            self._encrypt_dump(dump_path, backup_file, timestamp)
            self._verify_backup(backup_file)

            logger.info("Backup completed successfully: %s", backup_file)
            return str(backup_file)

        except Exception as e:
            logger.exception("Backup failed: %s", e)
            self._safe_remove(backup_file)
            self.alert_manager.create_alert(
                title="Database Backup Failed",
                description=f"Automated backup failed with error: {str(e)}",
                severity=AlertSeverity.CRITICAL,
                component="BackupManager"
            )
            return None
        finally:
            self._safe_remove(dump_path)

    def _backup_backend(self) -> str:
        database_url = (self.database_url or "").strip()
        if not database_url:
            raise ValueError("DATABASE_URL is not configured for backup")
        return urlparse(database_url).scheme.lower()

    def _dump_suffix(self) -> str:
        scheme = self._backup_backend()
        if scheme.startswith("postgres"):
            return ".sql"
        if scheme.startswith("sqlite"):
            return ".db"
        if scheme.startswith("neo4j"):
            return ".dump"
        raise ValueError(f"Unsupported database backend for backup: {scheme}")

    def _create_database_dump(self, dump_path: Path) -> None:
        scheme = self._backup_backend()
        if scheme.startswith("postgres"):
            self._dump_postgres(dump_path)
            return
        if scheme.startswith("sqlite"):
            self._dump_sqlite(dump_path)
            return
        if scheme.startswith("neo4j"):
            self._dump_neo4j(dump_path)
            return
        raise ValueError(f"Unsupported database backend for backup: {scheme}")

    def _dump_postgres(self, dump_path: Path) -> None:
        tool = self.backup_tool_path or shutil.which("pg_dump")
        if not tool:
            raise FileNotFoundError("pg_dump is required for PostgreSQL backups but was not found")

        env = os.environ.copy()
        parsed = urlparse(self.database_url or "")
        if parsed.password:
            env["PGPASSWORD"] = unquote(parsed.password)

        args = [tool, "--format=plain", "--no-owner", "--no-privileges", "--file", str(dump_path)]
        if parsed.hostname:
            args.extend(["--host", parsed.hostname])
        if parsed.port:
            args.extend(["--port", str(parsed.port)])
        if parsed.username:
            args.extend(["--username", unquote(parsed.username)])

        db_name = parsed.path.lstrip("/")
        if not db_name:
            raise ValueError("DATABASE_URL does not include a PostgreSQL database name")
        args.append(db_name)

        result = subprocess.run(args, env=env, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "pg_dump failed")

    def _dump_sqlite(self, dump_path: Path) -> None:
        parsed = urlparse(self.database_url or "")
        source = parsed.path
        if parsed.netloc and not source:
            source = parsed.netloc
        source = unquote(source)
        if os.name == "nt":
            source = source.lstrip("/\\")
        if source == ":memory:":
            raise ValueError("In-memory SQLite databases cannot be backed up to disk")
        if not source:
            raise ValueError("DATABASE_URL does not include a SQLite database path")

        source_path = Path(source)
        if not source_path.exists():
            raise FileNotFoundError(f"SQLite database file not found: {source_path}")

        with sqlite3.connect(str(source_path)) as source_conn:
            with sqlite3.connect(str(dump_path)) as target_conn:
                source_conn.backup(target_conn)

    def _dump_neo4j(self, dump_path: Path) -> None:
        tool = self.backup_tool_path or shutil.which("neo4j-admin")
        if not tool:
            raise FileNotFoundError("neo4j-admin is required for Neo4j backups but was not found")

        parsed = urlparse(self.database_url or "")
        db_name = parsed.path.lstrip("/") or os.getenv("NEO4J_DATABASE", "neo4j")
        uri = os.getenv("AEGIS_NEO4J_URI") or os.getenv("NEO4J_URI")
        user = os.getenv("AEGIS_NEO4J_USER") or os.getenv("NEO4J_USER")
        password = os.getenv("AEGIS_NEO4J_PASSWORD") or os.getenv("NEO4J_PASSWORD")
        if not (uri and user and password):
            raise ValueError("Neo4j backup requires AEGIS_NEO4J_URI/USER/PASSWORD or NEO4J_* equivalents")

        args = [tool, "database", "dump", db_name, f"--to-path={dump_path.parent}"]
        env = os.environ.copy()
        env["NEO4J_USERNAME"] = user
        env["NEO4J_PASSWORD"] = password
        result = subprocess.run(args, env=env, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "neo4j-admin dump failed")

    def _load_encryption_key(self) -> bytes:
        raw_key = self.backup_encryption_key or os.getenv("BACKUP_ENCRYPTION_KEY") or os.getenv("AEGIS_BACKUP_ENCRYPTION_KEY")
        if not raw_key:
            raise ValueError("BACKUP_ENCRYPTION_KEY is required for encrypted backups")

        try:
            key = base64.b64decode(raw_key, validate=True)
        except Exception as exc:
            raise ValueError(f"BACKUP_ENCRYPTION_KEY must be base64-encoded: {exc}") from exc
        if len(key) != _AES_GCM_KEY_SIZE:
            raise ValueError(f"BACKUP_ENCRYPTION_KEY must decode to {_AES_GCM_KEY_SIZE} bytes")
        return key

    def _encrypt_dump(self, dump_path: Path, backup_path: Path, timestamp: str) -> None:
        plaintext = dump_path.read_bytes()
        if not plaintext:
            raise ValueError("Database dump is empty")

        key = self._load_encryption_key()
        nonce = os.urandom(_AES_GCM_NONCE_SIZE)
        cipher = AESGCM(key)
        metadata = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "timestamp": timestamp,
            "backend": self._backup_backend(),
            "source": str(self.database_url),
            "sha256": hashlib.sha256(plaintext).hexdigest(),
        }
        header = json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data=header)
        with backup_path.open("wb") as handle:
            handle.write(_BACKUP_MAGIC)
            handle.write(len(header).to_bytes(4, "big"))
            handle.write(header)
            handle.write(nonce)
            handle.write(ciphertext)

    def _verify_backup(self, backup_path: Path) -> None:
        if not backup_path.exists():
            raise FileNotFoundError(f"Backup file was not created: {backup_path}")
        if backup_path.stat().st_size <= len(_BACKUP_MAGIC):
            raise ValueError("Encrypted backup file is empty")

        payload = backup_path.read_bytes()
        if not payload.startswith(_BACKUP_MAGIC):
            raise ValueError("Backup file is missing expected encryption header")
        header_len_offset = len(_BACKUP_MAGIC)
        if len(payload) < header_len_offset + 4 + _AES_GCM_NONCE_SIZE:
            raise ValueError("Backup file is truncated")
        header_len = int.from_bytes(payload[header_len_offset:header_len_offset + 4], "big")
        header_start = header_len_offset + 4
        header_end = header_start + header_len
        if len(payload) < header_end + _AES_GCM_NONCE_SIZE:
            raise ValueError("Backup file is truncated")
        header = payload[header_start:header_end]
        nonce = payload[header_end:header_end + _AES_GCM_NONCE_SIZE]
        ciphertext = payload[header_end + _AES_GCM_NONCE_SIZE:]

        key = self._load_encryption_key()
        cipher = AESGCM(key)
        plaintext = cipher.decrypt(nonce, ciphertext, associated_data=header)
        if not plaintext:
            raise ValueError("Backup verification failed: decrypted payload is empty")
        metadata = json.loads(header.decode("utf-8"))
        expected_sha = metadata.get("sha256")
        if expected_sha != hashlib.sha256(plaintext).hexdigest():
            raise ValueError("Backup verification failed: checksum mismatch")

    @staticmethod
    def _safe_remove(path: Path) -> None:
        try:
            if path.exists():
                path.unlink()
        except Exception:
            logger.debug("Failed to remove temporary backup artifact", exc_info=True)

    def clean_stale_backups(self):
        """Deletes backups older than retention_days."""
        cutoff_date = datetime.now() - timedelta(days=self.retention_days)
        try:
            for filename in os.listdir(self.backup_dir):
                filepath = Path(self.backup_dir) / filename
                if filepath.is_file():
                    file_mtime = datetime.fromtimestamp(filepath.stat().st_mtime)
                    if file_mtime < cutoff_date:
                        filepath.unlink()
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
