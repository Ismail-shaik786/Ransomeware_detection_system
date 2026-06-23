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

        # ── Behaviour flags ──────────────────────────────────────────────────
        if "MASS_RENAME" in stats.flags:
            score += config.RISK_WEIGHT_MASS_RENAME
            reasons.append(
                f"Mass renaming detected ({stats.renames} renames in "
                f"{config.BURST_WINDOW_SECONDS}s window)"
            )

        if "HEAVY_MODIFICATIONS" in stats.flags:
            score += config.RISK_WEIGHT_HEAVY_MOD
            reasons.append(
                f"Heavy file modifications ({stats.modifications} in "
                f"{config.BURST_WINDOW_SECONDS}s window)"
            )

        if "RAPID_DELETION" in stats.flags:
            score += config.RISK_WEIGHT_RAPID_DELETION
            reasons.append(
                f"Rapid file deletions ({stats.deletions} in "
                f"{config.BURST_WINDOW_SECONDS}s window)"
            )

        if "SUSPICIOUS_EXTENSION" in stats.flags:
            score += config.RISK_WEIGHT_SUSPICIOUS_EXT
            reasons.append(
                f"Suspicious extension change detected "
                f"({stats.suspicious_ext_changes} files)"
            )

        if "BURST_ACTIVITY" in stats.flags:
            score += config.RISK_WEIGHT_BURST_ACTIVITY
            reasons.append(
                f"Burst activity spike ({stats.total_events} events in "
                f"{config.BURST_WINDOW_SECONDS}s window)"
            )

        # ── Entropy signal ───────────────────────────────────────────────────
        from detector.entropy import classify_entropy, entropy_risk_points  # noqa: PLC0415
        entropy_class = classify_entropy(entropy_score)
        entropy_pts = entropy_risk_points(entropy_score)
        if entropy_pts > 0:
            score += entropy_pts
            reasons.append(
                f"High file entropy detected (score={entropy_score:.3f}, "
                f"class={entropy_class})"
            )

        # ── Process signal ───────────────────────────────────────────────────
        if suspicious_process:
            score += config.RISK_WEIGHT_SUSPICIOUS_PROCESS
            reasons.append("Known ransomware-simulation process active")

        # ── Cap at 100 ───────────────────────────────────────────────────────
        score = min(score, 100)

        # ── Classify ─────────────────────────────────────────────────────────
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
