"""
response/containment.py
=======================
Containment Engine.

When the risk score exceeds the RANSOMWARE threshold this engine:

  1. Triggers an immediate backup of monitored files.
  2. Saves incident evidence (event snapshot).
  3. Generates an alert message.
  4. Terminates any running approved simulation/test processes.
  5. Generates an incident report.

⚠️  SAFETY
-----------
Process termination is strictly limited to names listed in
config.APPROVED_SIMULATION_PROCESSES.  No system or arbitrary processes
are ever targeted.
"""

import os
from datetime import datetime
from typing import List

import config
from detector.risk_engine import RiskReport
from process.process_monitor import ProcessMonitor
from response.backup_manager import BackupManager
from utils import logger as log_module
from utils.helpers import ensure_dir, readable_timestamp, timestamp_str


class ContainmentEngine:
    """
    Orchestrates the full containment workflow when ransomware is detected.

    Usage
    -----
    engine = ContainmentEngine(watch_dir)
    actions = engine.respond(risk_report, affected_file)
    """

    def __init__(self, watch_dir: str) -> None:
        self.watch_dir = watch_dir
        self._backup_manager = BackupManager()
        self._process_monitor = ProcessMonitor()

    def respond(self, report: RiskReport, affected_file: str) -> List[str]:
        """
        Execute the full containment response.

        Parameters
        ----------
        report        : RiskReport that triggered this containment.
        affected_file : The file path that was last modified / renamed.

        Returns
        -------
        List[str] – human-readable descriptions of each action taken.
        """
        actions: List[str] = []

        # ── Step 1: Create backup ────────────────────────────────────────────
        backup_path, backed_up = self._backup_manager.create_backup(self.watch_dir)
        actions.append(
            f"Backup created at {backup_path} ({len(backed_up)} file(s))"
        )

        # ── Step 2: Save incident evidence ──────────────────────────────────
        evidence_path = self._save_evidence(report, affected_file, backup_path)
        actions.append(f"Evidence saved to {evidence_path}")

        # ── Step 3: Terminate approved simulation processes ──────────────────
        flagged = self._process_monitor.scan()
        for proc_info in flagged:
            if proc_info.is_simulation:
                success = self._process_monitor.terminate_simulation_process(
                    proc_info.pid
                )
                if success:
                    actions.append(
                        f"Simulation process terminated: {proc_info.name} "
                        f"(PID {proc_info.pid})"
                    )
                    log_module.log_event(
                        "PROCESS_TERMINATED",
                        f"{proc_info.name} PID={proc_info.pid}",
                    )

        # ── Step 4: Log the incident ─────────────────────────────────────────
        log_module.log_incident(
            reason=" | ".join(report.reasons) if report.reasons else "High risk score",
            risk_score=report.score,
            files_affected=[affected_file],
            actions_taken=actions,
        )

        return actions

    # ─────────────────────────── private ─────────────────────────────────────

    def _save_evidence(
        self, report: RiskReport, affected_file: str, backup_path: str
    ) -> str:
        """Write a plain-text evidence snapshot and return its path."""
        ensure_dir(config.REPORT_DIR)
        ts = timestamp_str()
        evidence_path = os.path.join(config.REPORT_DIR, f"incident_report_{ts}.txt")

        lines = [
            "=" * 60,
            "       RANSOMWARE GUARD – INCIDENT REPORT",
            "=" * 60,
            f"  Incident Time  : {readable_timestamp()}",
            f"  Risk Score     : {report.score} / 100  [{report.level}]",
            f"  Entropy Score  : {report.entropy_score:.4f} ({report.entropy_classification})",
            f"  File Affected  : {affected_file}",
            f"  Backup Location: {backup_path}",
            "",
            "── Detection Reasons ──────────────────────────────────────",
        ]
        for reason in report.reasons:
            lines.append(f"  • {reason}")

        lines += [
            "",
            "── Status ──────────────────────────────────────────────────",
            "  Containment   : ACTIVE",
            "  Recovery      : PENDING (run recovery manually if needed)",
            "=" * 60,
            "",
        ]

        with open(evidence_path, "w") as fh:
            fh.write("\n".join(lines))

        return evidence_path
