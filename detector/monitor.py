"""
detector/monitor.py
===================
Real-Time Directory Monitor.

Uses the *watchdog* library to watch a directory for file-system events
and feeds them into the behaviour analyser and risk engine.

Events captured
---------------
  • File created
  • File modified
  • File deleted
  • File renamed / moved
"""

import os
import threading
import time
from typing import Callable, Optional

from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

import config
from detector.behavior import BehaviorAnalyzer, BehaviorStats
from detector.entropy import analyse_file_entropy
from detector.risk_engine import RiskEngine, RiskReport
from utils import logger as log_module
from utils.helpers import file_extension, readable_timestamp


class RansomwareEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler that processes each file-system event,
    updates the behaviour analyser, runs the risk engine, and invokes
    user-supplied callbacks.

    Parameters
    ----------
    on_alert : Called whenever risk level is SUSPICIOUS or RANSOMWARE.
                Signature: on_alert(report: RiskReport, event_path: str)
    on_event : Called for every file-system event.
                Signature: on_event(event_type: str, path: str)
    """

    def __init__(
        self,
        on_alert: Callable[[RiskReport, str], None],
        on_event: Callable[[str, str], None],
    ) -> None:
        super().__init__()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.risk_engine = RiskEngine()
        self.on_alert = on_alert
        self.on_event = on_event
        self._lock = threading.Lock()

        # Track the latest entropy score across events
        self._last_entropy: float = 0.0
        self._suspicious_process: bool = False

    # ─────────────────────── watchdog callbacks ───────────────────────────────

    def on_created(self, event: FileCreatedEvent) -> None:
        if not event.is_directory:
            self._handle("CREATED", event.src_path)

    def on_modified(self, event: FileModifiedEvent) -> None:
        if not event.is_directory:
            self._handle("MODIFIED", event.src_path)

    def on_deleted(self, event: FileDeletedEvent) -> None:
        if not event.is_directory:
            self._handle("DELETED", event.src_path)

    def on_moved(self, event: FileMovedEvent) -> None:
        if not event.is_directory:
            # Use destination path to check for suspicious extensions
            self._handle("RENAMED", event.dest_path)

    # ─────────────────────── internal logic ──────────────────────────────────

    def _handle(self, event_type: str, path: str) -> None:
        """Core handler: update analyser, compute risk, fire callbacks."""
        with self._lock:
            # Skip backup dir to avoid feedback loops
            if config.BACKUP_DIR in path:
                return

            # Record event in the behaviour window
            self.behavior_analyzer.record_event(event_type, path)

            # Entropy analysis (only for modify/create events on real files)
            entropy_score: float = 0.0
            if event_type in ("MODIFIED", "CREATED") and os.path.isfile(path):
                result = analyse_file_entropy(path)
                if result is not None:
                    # Only update persistent entropy for scorable file types.
                    # Skipped extensions (ZIP, images, video …) return None;
                    # we deliberately do NOT carry their score forward to avoid
                    # false-positive bleed into the next unrelated event.
                    entropy_score = result
                    self._last_entropy = result

            # Run risk engine using only the current event's entropy.
            # The old code multiplied _last_entropy * 0.5 here, which caused
            # high entropy from a ZIP write to pollute the risk score of
            # subsequent plain-text events.  That decay is now removed.
            stats: BehaviorStats = self.behavior_analyzer.analyse()
            report: RiskReport = self.risk_engine.evaluate(
                stats,
                entropy_score=entropy_score,
                suspicious_process=self._suspicious_process,
            )

            # Log to events.log
            log_module.log_event(
                event_type=event_type,
                message=path,
                entropy=entropy_score if entropy_score > 0 else None,
                risk_score=report.score,
            )

            # Fire event callback
            self.on_event(event_type, path)

            # Fire alert callback if warranted
            if report.level in ("SUSPICIOUS", "RANSOMWARE"):
                self.on_alert(report, path)

    def update_process_flag(self, suspicious: bool) -> None:
        """Allow the process monitor to push its detection state in."""
        with self._lock:
            self._suspicious_process = suspicious


class DirectoryMonitor:
    """
    Manages the watchdog Observer lifecycle.

    Usage
    -----
    monitor = DirectoryMonitor(path, on_alert_cb, on_event_cb)
    monitor.start()
    ...
    monitor.stop()
    """

    def __init__(
        self,
        watch_path: str,
        on_alert: Callable[[RiskReport, str], None],
        on_event: Callable[[str, str], None],
    ) -> None:
        self.watch_path = watch_path
        self._handler = RansomwareEventHandler(on_alert, on_event)
        self._observer = Observer()
        self._observer.schedule(self._handler, watch_path, recursive=True)

    def start(self) -> None:
        """Start the background watchdog thread."""
        self._observer.start()

    def stop(self) -> None:
        """Gracefully stop the watchdog thread."""
        self._observer.stop()
        self._observer.join()

    def update_process_flag(self, suspicious: bool) -> None:
        """Relay process-monitor state to the event handler."""
        self._handler.update_process_flag(suspicious)

    @property
    def behavior_analyzer(self) -> BehaviorAnalyzer:
        """Expose the behaviour analyser for dashboard stats."""
        return self._handler.behavior_analyzer
