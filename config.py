"""
config.py
=========
Central configuration file for Ransomware Guard.
All tunable parameters are defined here for easy customisation.

False-Positive Reduction Notes
--------------------------------
Thresholds have been calibrated to tolerate common benign workloads:
  • Copying large files / extracting archives → many MODIFIED events
  • Video rendering / software installs       → burst CPU + many file events
  • Editing documents repeatedly              → repeated MODIFIED events
  • ZIP compression                           → high-entropy output + renames

Key mitigations applied:
  1. Wider BURST_WINDOW_SECONDS (30 s) spreads normal spikes over time.
  2. Higher rename / mod / delete thresholds before flags trigger.
  3. Benign high-entropy extensions (compressed, media) are excluded from
     entropy scoring (see ENTROPY_SKIP_EXTENSIONS).
  4. SUSPICIOUS_CPU_THRESHOLD raised to 90 % (video rendering routinely
     maxes cores; 80 % is far too low).
  5. RANSOMWARE level requires BOTH behavioural flags AND high entropy —
     single-signal triggers only reach SUSPICIOUS (see risk_engine.py).
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
ENTROPY_HIGH_THRESHOLD: float = 7.2     # above → likely encrypted / compressed
                                          # raised from 7.0 – ZIP/media sit ~7.0-7.5

# ─────────────────────────────────────────────────────────────────────────────
# RISK SCORE ENGINE
# ─────────────────────────────────────────────────────────────────────────────
RISK_SCORE_NORMAL: int = 40         # 0-40   → Normal
RISK_SCORE_SUSPICIOUS: int = 70     # 41-70  → Suspicious
# 71-100 → Potential Ransomware (triggers containment)

# Weighted points per indicator
RISK_WEIGHT_MASS_RENAME: int = 30
RISK_WEIGHT_HIGH_ENTROPY: int = 20     # reduced from 25 – entropy alone is not proof
RISK_WEIGHT_HEAVY_MOD: int = 15        # reduced from 20 – heavy mod is common (render/save)
RISK_WEIGHT_SUSPICIOUS_PROCESS: int = 25
RISK_WEIGHT_SUSPICIOUS_EXT: int = 25   # raised from 20 – strongest single signal
RISK_WEIGHT_RAPID_DELETION: int = 15
RISK_WEIGHT_BURST_ACTIVITY: int = 5    # reduced from 10 – installs/renders are bursty

# ─────────────────────────────────────────────────────────────────────────────
# BEHAVIOUR THRESHOLDS
# ─────────────────────────────────────────────────────────────────────────────
# Window in seconds to assess "burst" activity
# Raised from 10 s → 30 s so that normal file copies / renders spread out
# and do NOT accumulate enough events to hit the thresholds below.
BURST_WINDOW_SECONDS: int = 30

# Number of renames within the burst window to flag mass-rename.
# Raised from 5 → 12: archiving tools (7-Zip, tar) commonly produce 5-10
# temp renames during a single compression run.
MASS_RENAME_THRESHOLD: int = 12

# Number of modifications within the burst window to flag heavy modification.
# Raised from 10 → 25: video rendering, large-file copies, and document
# auto-saves routinely modify 10-20 files in 30 seconds.
HEAVY_MOD_THRESHOLD: int = 25

# Number of deletions within the burst window to flag rapid deletion.
# Raised from 5 → 10: software installers delete temp/staging files in bulk.
RAPID_DELETE_THRESHOLD: int = 10

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

# ── Entropy false-positive whitelist ──────────────────────────────────────────
# These extensions are inherently high-entropy by design (compressed or
# pre-encoded formats).  Scoring entropy on them generates false positives
# because they always appear "encrypted" even when written by benign programs.
# Files matching these extensions are SKIPPED during entropy analysis.
ENTROPY_SKIP_EXTENSIONS: list = [
    # Compressed archives
    ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".tgz", ".zst",
    # Disk / package images
    ".iso", ".img", ".dmg", ".deb", ".rpm", ".apk", ".msi", ".exe",
    # Video
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v",
    # Audio
    ".mp3", ".aac", ".ogg", ".flac", ".m4a", ".wma",
    # Raster images (JPEG/PNG are already compressed)
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif",
    # Raw/pre-encrypted containers
    ".pdf",   # PDFs with embedded images are often high-entropy
    ".psd", ".xcf",
    # Python / system compiled artefacts (bytecode)
    ".pyc", ".pyo",
    # Office Open XML (docx/xlsx are ZIP archives internally)
    ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
]

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

# CPU usage % above which a process is flagged as suspicious.
# Raised from 80 % → 90 %: video rendering, compilation, and software
# installs routinely saturate cores.  90 % is a more realistic threshold
# that still catches crypto-mining / ransomware key-gen loops.
SUSPICIOUS_CPU_THRESHOLD: float = 90.0

# Minimum number of DISTINCT behavioural flags required before entropy
# alone can push a score into RANSOMWARE territory.
# Prevents a single large ZIP write from triggering containment.
MIN_BEHAVIOUR_FLAGS_FOR_RANSOMWARE: int = 2

# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD REFRESH
# ─────────────────────────────────────────────────────────────────────────────
DASHBOARD_REFRESH_SECONDS: float = 3.0   # How often the live stats panel refreshes
