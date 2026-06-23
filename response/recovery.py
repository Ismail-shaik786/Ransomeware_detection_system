"""
response/recovery.py
====================
Recovery Engine.

Restores the monitored directory from the most recent backup and
generates a human-readable recovery report.
"""

import os
from typing import Tuple

import config
from response.backup_manager import BackupManager
from utils import logger as log_module
from utils.helpers import ensure_dir, readable_timestamp, timestamp_str


class RecoveryEngine:
    """
    Restores monitored files from the latest available backup.

    Usage
    -----
    engine = RecoveryEngine(watch_dir)
    report_path = engine.recover()
    """

    def __init__(self, watch_dir: str) -> None:
        self.watch_dir = watch_dir
        self._backup_manager = BackupManager()

    def recover(self) -> Tuple[bool, str]:
        """
        Restore files from the latest backup.

        Returns
        -------
        (success: bool, report_path: str)
          success     – True if at least one file was restored.
          report_path – Path of the generated recovery report.
        """
        backup_path = self._backup_manager.get_latest_backup()

        if not backup_path:
            msg = "No backups found – nothing to recover."
            log_module.log_event("RECOVERY_FAILED", msg)
            return False, self._write_report(0, 0.0, None, msg)

        files_restored, elapsed = self._backup_manager.restore_backup(
            backup_path, self.watch_dir
        )

        success = files_restored > 0
        status = "SUCCESS" if success else "FAILED – no files found in backup"

        log_module.log_event(
            "RECOVERY_COMPLETE",
            f"Restored {files_restored} file(s) in {elapsed:.2f}s "
            f"from {backup_path}",
        )

        report_path = self._write_report(
            files_restored, elapsed, backup_path, status
        )
        return success, report_path

    # ─────────────────────────── private ─────────────────────────────────────

    def _write_report(
        self,
        files_restored: int,
        elapsed: float,
        backup_used: str | None,
        status: str,
    ) -> str:
        """Write a recovery report and return its path."""
        ensure_dir(config.REPORT_DIR)
        ts = timestamp_str()
        report_path = os.path.join(config.REPORT_DIR, f"recovery_report_{ts}.txt")

        lines = [
            "=" * 60,
            "       RANSOMWARE GUARD – RECOVERY REPORT",
            "=" * 60,
            f"  Recovery Time  : {readable_timestamp()}",
            f"  Backup Used    : {backup_used or 'None'}",
            f"  Files Restored : {files_restored}",
            f"  Recovery Time  : {elapsed:.3f} seconds",
            f"  Status         : {status}",
            "=" * 60,
            "",
        ]

        with open(report_path, "w") as fh:
            fh.write("\n".join(lines))

        return report_path
