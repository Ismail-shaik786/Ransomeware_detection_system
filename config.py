"""
config.py
=========
Central configuration file for Ransomware Guard.
All tunable parameters are defined here for easy customisation.
"""

import os

# ─────────────────────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))

BACKUP_DIR: str = os.path.join(BASE_DIR, "backups")
LOG_DIR: str = os.path.join(BASE_DIR, "logs")
REPORT_DIR: str = os.path.join(BASE_DIR, "reports")

LOG_EVENTS_FILE: str = os.path.join(LOG_DIR, "events.log")
LOG_INCIDENTS_FILE: str = os.path.join(LOG_DIR, "incidents.log")

# ─────────────────────────────────────────────────────────────────────────────
# ENTROPY
# ─────────────────────────────────────────────────────────────────────────────
# Shannon entropy ranges (bits per byte, max = 8)
ENTROPY_LOW_THRESHOLD: float = 3.5       # below → normal text / data
ENTROPY_HIGH_THRESHOLD: float = 7.0     # above → likely encrypted / compressed

# ─────────────────────────────────────────────────────────────────────────────
# RISK SCORE ENGINE
# ─────────────────────────────────────────────────────────────────────────────
RISK_SCORE_NORMAL: int = 40         # 0-40   → Normal
RISK_SCORE_SUSPICIOUS: int = 70     # 41-70  → Suspicious
# 71-100 → Potential Ransomware (triggers containment)

# Weighted points per indicator
RISK_WEIGHT_MASS_RENAME: int = 30
RISK_WEIGHT_HIGH_ENTROPY: int = 25
RISK_WEIGHT_HEAVY_MOD: int = 20
RISK_WEIGHT_SUSPICIOUS_PROCESS: int = 25
RISK_WEIGHT_SUSPICIOUS_EXT: int = 20
RISK_WEIGHT_RAPID_DELETION: int = 15
RISK_WEIGHT_BURST_ACTIVITY: int = 10

# ─────────────────────────────────────────────────────────────────────────────
# BEHAVIOUR THRESHOLDS
# ─────────────────────────────────────────────────────────────────────────────
# Window in seconds to assess "burst" activity
BURST_WINDOW_SECONDS: int = 10

# Number of renames within the burst window to flag mass-rename
MASS_RENAME_THRESHOLD: int = 5

# Number of modifications within the burst window to flag heavy modification
HEAVY_MOD_THRESHOLD: int = 10

# Number of deletions within the burst window to flag rapid deletion
RAPID_DELETE_THRESHOLD: int = 5

# Known ransomware-related file extensions
SUSPICIOUS_EXTENSIONS: list = [
    ".locked", ".encrypted", ".crypt", ".crypto", ".enc",
    ".rnsmwr", ".zepto", ".locky", ".cerber", ".aaa",
    ".abc", ".xyz", ".ecc", ".ezz", ".exx",
    ".vvv", ".micro", ".ttt", ".mp3", ".pays",
    ".zzzzz", ".fucked", ".lol", ".ransomed",
    ".kraken", ".darkness", ".nochance", ".wannacry",
]

# ─────────────────────────────────────────────────────────────────────────────
# FILE MONITORING
# ─────────────────────────────────────────────────────────────────────────────
# Extensions to include in entropy analysis (empty list = all files)
MONITORED_EXTENSIONS: list = []   # e.g. [".txt", ".docx", ".pdf"]

# Maximum file size (bytes) to perform entropy analysis on
MAX_FILE_SIZE_FOR_ENTROPY: int = 10 * 1024 * 1024  # 10 MB

# ─────────────────────────────────────────────────────────────────────────────
# PROCESS MONITORING
# ─────────────────────────────────────────────────────────────────────────────
# Names of approved simulation / test processes that may be safely terminated.
# IMPORTANT: Only add process names of your own safe test scripts here.
APPROVED_SIMULATION_PROCESSES: list = [
    "simulate_ransomware.py",
    "ransomware_sim.py",
    "test_attack.py",
    "safe_attack_sim.py",
]

# CPU usage % above which a process is flagged as suspicious
SUSPICIOUS_CPU_THRESHOLD: float = 80.0

# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD REFRESH
# ─────────────────────────────────────────────────────────────────────────────
DASHBOARD_REFRESH_SECONDS: float = 3.0   # How often the live stats panel refreshes
