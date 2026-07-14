from __future__ import annotations

import base64
import json
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from database.automated_backup import DatabaseBackupManager
from src.config.loaders import load_environment, load_settings


def _backup_key() -> str:
    return base64.b64encode(b"0" * 32).decode("ascii")


def _decrypt_backup(path: Path, key: str) -> bytes:
    payload = path.read_bytes()
    magic = b"AEGIS-BACKUP-1\n"
    assert payload.startswith(magic)
    header_len = int.from_bytes(payload[len(magic) : len(magic) + 4], "big")
    header_start = len(magic) + 4
    header_end = header_start + header_len
    header = payload[header_start:header_end]
    nonce = payload[header_end : header_end + 12]
    ciphertext = payload[header_end + 12 :]
    cipher = AESGCM(base64.b64decode(key))
    return cipher.decrypt(nonce, ciphertext, associated_data=header)


def test_successful_sqlite_backup_generates_encrypted_restorable_dump(tmp_path: Path) -> None:
    db_path = tmp_path / "source.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE transfers (id INTEGER PRIMARY KEY, amount INTEGER)")
        conn.execute("INSERT INTO transfers (amount) VALUES (125)")
        conn.commit()

    backup_dir = tmp_path / "backups"
    manager = DatabaseBackupManager(
        backup_dir=str(backup_dir),
        database_url=f"sqlite:///{db_path}",
        backup_encryption_key=_backup_key(),
    )

    backup_path = manager.trigger_backup()

    assert backup_path is not None
    backup_file = Path(backup_path)
    assert backup_file.exists()
    assert backup_file.stat().st_size > 0
    assert not backup_file.read_bytes().startswith(b"ENCRYPTED_DATABASE_DUMP_DATA")

    decrypted = _decrypt_backup(backup_file, _backup_key())
    restored_db = tmp_path / "restored.db"
    restored_db.write_bytes(decrypted)
    with sqlite3.connect(restored_db) as conn:
        amount = conn.execute("SELECT amount FROM transfers").fetchone()[0]
    assert amount == 125


def test_backup_cleanup_removes_expired_files(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    expired = backup_dir / "expired.enc"
    active = backup_dir / "active.enc"
    expired.write_bytes(b"old")
    active.write_bytes(b"new")
    old_ts = 1_600_000_000
    os.utime(expired, (old_ts, old_ts))

    manager = DatabaseBackupManager(
        backup_dir=str(backup_dir),
        retention_days=7,
        database_url="sqlite:///ignored.db",
        backup_encryption_key=_backup_key(),
    )

    manager.clean_stale_backups()

    assert not expired.exists()
    assert active.exists()


def test_backup_failure_triggers_alert(tmp_path: Path) -> None:
    manager = DatabaseBackupManager(
        backup_dir=str(tmp_path / "backups"),
        database_url="sqlite:///missing.db",
        backup_encryption_key=_backup_key(),
    )
    manager.alert_manager.create_alert = Mock()

    result = manager.trigger_backup()

    assert result is None
    manager.alert_manager.create_alert.assert_called_once()


def test_encryption_failure_triggers_alert(tmp_path: Path) -> None:
    db_path = tmp_path / "source.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE sample (id INTEGER)")
        conn.commit()

    manager = DatabaseBackupManager(
        backup_dir=str(tmp_path / "backups"),
        database_url=f"sqlite:///{db_path}",
        backup_encryption_key=_backup_key(),
    )
    manager.alert_manager.create_alert = Mock()

    with patch("database.automated_backup.AESGCM.encrypt", side_effect=RuntimeError("encryption failed")):
        result = manager.trigger_backup()

    assert result is None
    manager.alert_manager.create_alert.assert_called_once()


def test_dump_tool_failure_triggers_alert(tmp_path: Path) -> None:
    manager = DatabaseBackupManager(
        backup_dir=str(tmp_path / "backups"),
        database_url="postgresql+asyncpg://postgres:postgres@localhost:5432/aegis_db",
        backup_encryption_key=_backup_key(),
        backup_tool_path="pg_dump",
    )
    manager.alert_manager.create_alert = Mock()

    completed = SimpleNamespace(returncode=1, stdout="", stderr="pg_dump failed")
    with patch("database.automated_backup.shutil.which", return_value="pg_dump"), patch(
        "database.automated_backup.subprocess.run",
        return_value=completed,
    ):
        result = manager.trigger_backup()

    assert result is None
    manager.alert_manager.create_alert.assert_called_once()


def test_postgres_backup_uses_native_dump_tool(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    dump_contents = b"CREATE TABLE demo(id integer);"

    def fake_run(args, env=None, capture_output=None, text=None, check=None):
        out_index = args.index("--file") + 1
        Path(args[out_index]).write_bytes(dump_contents)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    manager = DatabaseBackupManager(
        backup_dir=str(backup_dir),
        database_url="postgresql+asyncpg://postgres:postgres@localhost:5432/aegis_db",
        backup_encryption_key=_backup_key(),
        backup_tool_path="pg_dump",
    )

    with patch("database.automated_backup.shutil.which", return_value="pg_dump"), patch(
        "database.automated_backup.subprocess.run",
        side_effect=fake_run,
    ):
        backup_path = manager.trigger_backup()

    assert backup_path is not None
    decrypted = _decrypt_backup(Path(backup_path), _backup_key())
    assert dump_contents in decrypted


def test_configuration_loading_includes_backup_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BACKUP_DIRECTORY", "tmp/backups")
    monkeypatch.setenv("BACKUP_DATABASE_URL", "sqlite:///var/data/a.db")
    monkeypatch.setenv("BACKUP_TOOL_PATH", "/usr/bin/pg_dump")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY", _backup_key())

    env = load_environment()
    settings = load_settings(environ={
        "BACKUP_DIRECTORY": "tmp/backups",
        "BACKUP_DATABASE_URL": "sqlite:///var/data/a.db",
        "BACKUP_TOOL_PATH": "/usr/bin/pg_dump",
        "BACKUP_ENCRYPTION_KEY": _backup_key(),
    })

    assert env.backup_directory == "tmp/backups"
    assert env.backup_database_url == "sqlite:///var/data/a.db"
    assert env.backup_tool_path == "/usr/bin/pg_dump"
    assert env.backup_encryption_key == _backup_key()
    assert settings.raw_environment.backup_directory == "tmp/backups"


def test_invalid_backup_directory_raises(tmp_path: Path) -> None:
    with patch.object(Path, "mkdir", side_effect=PermissionError("denied")):
        with pytest.raises(PermissionError):
            DatabaseBackupManager(
                backup_dir=str(tmp_path / "blocked"),
                database_url="sqlite:///ignored.db",
                backup_encryption_key=_backup_key(),
            )
