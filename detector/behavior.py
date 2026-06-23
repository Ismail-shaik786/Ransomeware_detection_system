"""
detector/behavior.py
====================
Behaviour Analysis Module.

Tracks file-system event patterns over a sliding time window and flags
known ransomware behavioural patterns such as:

  • Mass renaming (especially adding suspicious extensions)
  • Rapid file modifications
  • Rapid file deletions
  • Burst activity spikes
"""

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, List, Tuple

import config
from utils.helpers import file_extension


@dataclass
class BehaviorStats:
    """Snapshot of current behavioural counters."""
    renames: int = 0
    modifications: int = 0
    deletions: int = 0
    creations: int = 0
    suspicious_ext_changes: int = 0
    total_events: int = 0
    flags: List[str] = field(default_factory=list)


class BehaviorAnalyzer:
    """
    Maintains a sliding-window event queue and detects ransomware patterns.

    All timestamps are Unix epoch floats (time.time()).
    """

    def __init__(self) -> None:
        # Each entry is (timestamp, event_type, path)
        self._events: Deque[Tuple[float, str, str]] = deque()

        # Lifetime counters (never reset)
        self.total_renames: int = 0
        self.total_modifications: int = 0
        self.total_deletions: int = 0
        self.total_creations: int = 0
        self.total_suspicious_ext: int = 0

    # ─────────────────────────── public API ──────────────────────────────────

    def record_event(self, event_type: str, path: str) -> None:
        """
        Record a file-system event.

        Parameters
        ----------
        event_type : One of "CREATED", "MODIFIED", "DELETED", "RENAMED".
        path       : File path involved.
        """
        now = time.time()
        self._events.append((now, event_type, path))
        self._prune_old_events(now)

        # Update lifetime counters
        match event_type:
            case "RENAMED":
                self.total_renames += 1
                if self._is_suspicious_extension(path):
                    self.total_suspicious_ext += 1
            case "MODIFIED":
                self.total_modifications += 1
            case "DELETED":
                self.total_deletions += 1
            case "CREATED":
                self.total_creations += 1

    def analyse(self) -> BehaviorStats:
        """
        Evaluate current window and return a BehaviorStats snapshot.

        Returns
        -------
        BehaviorStats with detected flags.
        """
        now = time.time()
        self._prune_old_events(now)

        stats = BehaviorStats()
        flags: List[str] = []

        for _, etype, path in self._events:
            stats.total_events += 1
            match etype:
                case "RENAMED":
                    stats.renames += 1
                    if self._is_suspicious_extension(path):
                        stats.suspicious_ext_changes += 1
                case "MODIFIED":
                    stats.modifications += 1
                case "DELETED":
                    stats.deletions += 1
                case "CREATED":
                    stats.creations += 1

        # ── Flag: Mass Rename ────────────────────────────────────────────────
        if stats.renames >= config.MASS_RENAME_THRESHOLD:
            flags.append("MASS_RENAME")

        # ── Flag: Heavy Modifications ────────────────────────────────────────
        if stats.modifications >= config.HEAVY_MOD_THRESHOLD:
            flags.append("HEAVY_MODIFICATIONS")

        # ── Flag: Rapid Deletion ─────────────────────────────────────────────
        if stats.deletions >= config.RAPID_DELETE_THRESHOLD:
            flags.append("RAPID_DELETION")

        # ── Flag: Suspicious Extension Change ────────────────────────────────
        if stats.suspicious_ext_changes > 0:
            flags.append("SUSPICIOUS_EXTENSION")

        # ── Flag: General Burst Activity ─────────────────────────────────────
        if stats.total_events >= (
            config.MASS_RENAME_THRESHOLD + config.HEAVY_MOD_THRESHOLD
        ):
            flags.append("BURST_ACTIVITY")

        stats.flags = flags
        return stats

    def reset_window(self) -> None:
        """Clear the sliding-window event queue (does NOT reset lifetime counters)."""
        self._events.clear()

    # ─────────────────────────── private ─────────────────────────────────────

    def _prune_old_events(self, now: float) -> None:
        """Remove events older than the configured burst window."""
        cutoff = now - config.BURST_WINDOW_SECONDS
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    @staticmethod
    def _is_suspicious_extension(path: str) -> bool:
        """Return True if *path* ends with a known ransomware extension."""
        return file_extension(path) in config.SUSPICIOUS_EXTENSIONS
