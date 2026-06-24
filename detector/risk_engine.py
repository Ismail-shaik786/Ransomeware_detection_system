"""
detector/risk_engine.py
=======================
Risk Scoring Engine.

Aggregates indicators from the behaviour analyser, entropy module, and
process monitor into a single weighted risk score.

Score bands
-----------
  0 – 40  → NORMAL      (green)
 41 – 70  → SUSPICIOUS  (yellow)
 71 – 100 → RANSOMWARE  (red)

False-positive mitigations
--------------------------
  • Monotone-burst guard: if all burst activity is a single event type
    (e.g. 100 % MODIFIED events from a file copy / video render) the
    BURST_ACTIVITY and HEAVY_MODIFICATIONS flags are suppressed, because
    legitimate bulk-write operations are monotone whereas ransomware
    produces a mixed stream (CREATE → MODIFY → RENAME → DELETE).

  • Multi-signal gate: high entropy alone cannot escalate a score into
    RANSOMWARE territory.  At least MIN_BEHAVIOUR_FLAGS_FOR_RANSOMWARE
    distinct behavioural flags must also be present.  This prevents a
    single large ZIP/video write from triggering containment.
"""

from dataclasses import dataclass, field
from typing import List

import config
from detector.behavior import BehaviorStats


@dataclass
class RiskReport:
    """Full risk assessment for the current monitoring cycle."""
    score: int = 0
    level: str = "NORMAL"          # "NORMAL" | "SUSPICIOUS" | "RANSOMWARE"
    reasons: List[str] = field(default_factory=list)
    entropy_score: float = 0.0
    entropy_classification: str = "LOW"


class RiskEngine:
    """
    Calculates an aggregate risk score from multiple signals.

    Usage
    -----
    engine = RiskEngine()
    report = engine.evaluate(behavior_stats, entropy_score, suspicious_process_detected)
    """

    def evaluate(
        self,
        stats: BehaviorStats,
        entropy_score: float = 0.0,
        suspicious_process: bool = False,
    ) -> RiskReport:
        """
        Combine all signals into a RiskReport.

        Parameters
        ----------
        stats               : BehaviorStats snapshot from BehaviorAnalyzer.
        entropy_score       : Shannon entropy of the most recent file event (0-8).
        suspicious_process  : True if a known simulation process was detected.

        Returns
        -------
        RiskReport
        """
        score = 0
        reasons: List[str] = []

        # ── Monotone-burst guard ───────────────────────────────────────────
        # Ransomware produces a MIXED stream: it reads a file (CREATED temp
        # copy), writes ciphertext (MODIFIED), renames to .locked (RENAMED),
        # and deletes the original (DELETED).  Legitimate bulk operations
        # (file copy, video render, software install) are dominated by a
        # SINGLE event type.  If >85 % of window events share one type we
        # treat the burst as benign and suppress HEAVY_MOD + BURST flags.
        _active_flags = set(stats.flags)  # we may remove flags below
        if stats.total_events >= 5:
            _type_counts = [
                stats.renames,
                stats.modifications,
                stats.deletions,
                stats.creations,
            ]
            _dominant = max(_type_counts)
            _monotone = (_dominant / stats.total_events) >= 0.85
        else:
            _monotone = False

        # ── Behaviour flags ────────────────────────────────────────────────
        if "MASS_RENAME" in _active_flags:
            score += config.RISK_WEIGHT_MASS_RENAME
            reasons.append(
                f"Mass renaming detected ({stats.renames} renames in "
                f"{config.BURST_WINDOW_SECONDS}s window)"
            )

        if "HEAVY_MODIFICATIONS" in _active_flags and not _monotone:
            # Suppress if the burst is monotone (all-writes = file copy / render)
            score += config.RISK_WEIGHT_HEAVY_MOD
            reasons.append(
                f"Heavy file modifications ({stats.modifications} in "
                f"{config.BURST_WINDOW_SECONDS}s window)"
            )

        if "RAPID_DELETION" in _active_flags:
            score += config.RISK_WEIGHT_RAPID_DELETION
            reasons.append(
                f"Rapid file deletions ({stats.deletions} in "
                f"{config.BURST_WINDOW_SECONDS}s window)"
            )

        if "SUSPICIOUS_EXTENSION" in _active_flags:
            score += config.RISK_WEIGHT_SUSPICIOUS_EXT
            reasons.append(
                f"Suspicious extension change detected "
                f"({stats.suspicious_ext_changes} files)"
            )

        if "BURST_ACTIVITY" in _active_flags and not _monotone:
            # Suppress if the burst is monotone (single-type = benign workload)
            score += config.RISK_WEIGHT_BURST_ACTIVITY
            reasons.append(
                f"Burst activity spike ({stats.total_events} events in "
                f"{config.BURST_WINDOW_SECONDS}s window)"
            )

        # ── Entropy signal ─────────────────────────────────────────────────
        from detector.entropy import classify_entropy, entropy_risk_points  # noqa: PLC0415
        entropy_class = classify_entropy(entropy_score)
        entropy_pts = entropy_risk_points(entropy_score)
        if entropy_pts > 0:
            score += entropy_pts
            reasons.append(
                f"High file entropy detected (score={entropy_score:.3f}, "
                f"class={entropy_class})"
            )

        # ── Process signal ─────────────────────────────────────────────────
        if suspicious_process:
            score += config.RISK_WEIGHT_SUSPICIOUS_PROCESS
            reasons.append("Known ransomware-simulation process active")

        # ── Cap at 100 ─────────────────────────────────────────────────────
        score = min(score, 100)

        # ── Multi-signal gate ─────────────────────────────────────────────
        # If the number of distinct behavioural flags is below the minimum,
        # cap the score at SUSPICIOUS so entropy alone cannot trigger
        # containment.  This protects against false alarms from ZIP writes,
        # image conversions, or any other single-file high-entropy operation.
        behaviour_flag_count = len(
            [f for f in ("MASS_RENAME", "HEAVY_MODIFICATIONS",
                         "RAPID_DELETION", "SUSPICIOUS_EXTENSION",
                         "BURST_ACTIVITY")
             if f in _active_flags
             and not (f in ("HEAVY_MODIFICATIONS", "BURST_ACTIVITY") and _monotone)]
        )
        if (score > config.RISK_SCORE_SUSPICIOUS
                and behaviour_flag_count < config.MIN_BEHAVIOUR_FLAGS_FOR_RANSOMWARE
                and not suspicious_process):
            score = config.RISK_SCORE_SUSPICIOUS  # demote to SUSPICIOUS
            reasons.append(
                "[FP guard] Insufficient behavioural signals for RANSOMWARE — "
                "score capped at SUSPICIOUS threshold"
            )

        # ── Classify ────────────────────────────────────────────────────────
        if score <= config.RISK_SCORE_NORMAL:
            level = "NORMAL"
        elif score <= config.RISK_SCORE_SUSPICIOUS:
            level = "SUSPICIOUS"
        else:
            level = "RANSOMWARE"

        return RiskReport(
            score=score,
            level=level,
            reasons=reasons,
            entropy_score=entropy_score,
            entropy_classification=entropy_class,
        )
