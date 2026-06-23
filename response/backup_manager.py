"""
response/backup_manager.py
==========================
Automatic Backup Module.

Before any containment or recovery action, all monitored files are
backed up here.  Backups are:

  • Stored under  backups/<timestamp>/
  • Folder structure is preserved
  • Duplicate backups for unchanged files are skipped (hash comparison)
"""

import hashlib
import os
import shutil
from typing import Dict, List, Tuple

import config
from utils.helpers import ensure_dir, readable_timestamp, timestamp_str
from utils import logger as log_module


class BackupManager:
    """
    Creates and manages timestamped backups of a monitored directory.

    Usage
    -----
    bm = BackupManager()
    backup_path, files_backed_up = bm.create_backup(watch_dir)
    bm.list_backups()
    bm.restore_backup(backup_path, restore_target)
    """

    def __init__(self) -> None:
        ensure_dir(config.BACKUP_DIR)
        # Cache: file_path → last known sha256 to avoid duplicate backups
        self._hash_cache: Dict[str, str] = {}

    # ──────────────────────────── public API ─────────────────────────────────

    def create_backup(self, watch_dir: str) -> Tuple[str, List[str]]:
        """
        Copy all files from *watch_dir* into a new timestamped backup folder.

        Parameters
        ----------
        watch_dir : The directory being monitored.

        Returns
        -------
        (backup_path, [list of backed-up files])
        """
        ts = timestamp_str()
        backup_path = os.path.join(config.BACKUP_DIR, f"backup_{ts}")
        ensure_dir(backup_path)

        backed_up: List[str] = []

        for root, _dirs, files in os.walk(watch_dir):
            # Skip the backup directory itself
            if config.BACKUP_DIR in root:
                continue

            for filename in files:
                src = os.path.join(root, filename)
                if not os.path.isfile(src):
                    continue

                # Compute destination path, preserving folder hierarchy
                rel_path = os.path.relpath(src, watch_dir)
                dst = os.path.join(backup_path, rel_path)
                ensure_dir(os.path.dirname(dst))

                try:
                    file_hash = self._sha256(src)
                    # Skip if file has not changed since last backup
                    if self._hash_cache.get(src) == file_hash:
                        continue

                    shutil.copy2(src, dst)
                    self._hash_cache[src] = file_hash
                    backed_up.append(src)
                except (OSError, PermissionError) as exc:
                    log_module.log_event(
                        "BACKUP_ERROR", f"Could not backup {src}: {exc}"
                    )

        log_module.log_event(
            "BACKUP_CREATED",
            f"Backup at {backup_path} | {len(backed_up)} file(s) copied",
        )
        return backup_path, backed_up

    def list_backups(self) -> List[str]:
        """
        Return a sorted list of existing backup directory paths (oldest first).
        """
        try:
            entries = [
                os.path.join(config.BACKUP_DIR, d)
                for d in os.listdir(config.BACKUP_DIR)
                if os.path.isdir(os.path.join(config.BACKUP_DIR, d))
                and d.startswith("backup_")
            ]
            return sorted(entries)
        except OSError:
            return []

    def restore_backup(self, backup_path: str, restore_target: str) -> Tuple[int, float]:
        """
        Restore files from *backup_path* back into *restore_target*.

        Parameters
        ----------
        backup_path    : Path to the timestamped backup folder.
        restore_target : Directory to restore files into.

        Returns
        -------
        (number_of_files_restored, elapsed_seconds)
        """
        import time

        start = time.perf_counter()
        restored = 0

        ensure_dir(restore_target)

        for root, _dirs, files in os.walk(backup_path):
            for filename in files:
                src = os.path.join(root, filename)
                rel_path = os.path.relpath(src, backup_path)
                dst = os.path.join(restore_target, rel_path)
                ensure_dir(os.path.dirname(dst))

                try:
                    shutil.copy2(src, dst)
                    restored += 1
                except (OSError, PermissionError) as exc:
                    log_module.log_event(
                        "RESTORE_ERROR", f"Could not restore {src}: {exc}"
                    )

        elapsed = time.perf_counter() - start
        log_module.log_event(
            "RESTORE_COMPLETE",
            f"Restored {restored} file(s) from {backup_path} in {elapsed:.2f}s",
        )
        return restored, elapsed

    def get_latest_backup(self) -> str | None:
        """Return the path of the most-recent backup, or None if no backups exist."""
        backups = self.list_backups()
        return backups[-1] if backups else None

    # ─────────────────────────── private ─────────────────────────────────────

    @staticmethod
    def _sha256(path: str) -> str:
        """Compute the SHA-256 hex digest of a file (for change detection)."""
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
