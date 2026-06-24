# Changelog

All notable changes to CryptLock are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).  
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [1.1.0] – 2026-06-24

### Added
- **`ENTROPY_SKIP_EXTENSIONS`** config list — 35 inherently high-entropy
  file formats (ZIP, MP4, JPG, DOCX, etc.) are now excluded from entropy
  scoring, eliminating a major source of false positives.
- **`MIN_BEHAVIOUR_FLAGS_FOR_RANSOMWARE`** config parameter — requires at
  least 2 distinct behavioural flags before entropy can escalate a score
  into the RANSOMWARE band.
- **Monotone-burst guard** in `risk_engine.py` — suppresses
  `HEAVY_MODIFICATIONS` and `BURST_ACTIVITY` flags when ≥ 85 % of window
  events share a single type (e.g. all-MODIFIED from a video render or
  large-file copy).
- **`LICENSE`**, **`CONTRIBUTING.md`**, **`SECURITY.md`**,
  **`CODE_OF_CONDUCT.md`**, **`CHANGELOG.md`**, and GitHub Actions CI
  workflow for official open-source collaboration readiness.

### Changed
- `BURST_WINDOW_SECONDS`: 10 s → **30 s** (spreads normal spikes over time)
- `MASS_RENAME_THRESHOLD`: 5 → **12** (archiving tools produce 5-10 renames)
- `HEAVY_MOD_THRESHOLD`: 10 → **25** (renders/copies hit 10-20 mods easily)
- `RAPID_DELETE_THRESHOLD`: 5 → **10** (installers delete staging files)
- `SUSPICIOUS_CPU_THRESHOLD`: 80 % → **90 %** (video rendering maxes cores)
- `ENTROPY_HIGH_THRESHOLD`: 7.0 → **7.2** (ZIP/media naturally sit at 7.0-7.5)
- `RISK_WEIGHT_HIGH_ENTROPY`: 25 → **20** (entropy alone is not proof)
- `RISK_WEIGHT_HEAVY_MOD`: 20 → **15** (heavy mod is common in benign work)
- `RISK_WEIGHT_SUSPICIOUS_EXT`: 20 → **25** (strongest single signal)
- `RISK_WEIGHT_BURST_ACTIVITY`: 10 → **5** (installs/renders are bursty)
- README config table updated to reflect new thresholds.

### Fixed
- Removed entropy bleed-over: `_last_entropy * 0.5` decay caused a high
  entropy score from a ZIP write to pollute risk scores of subsequent
  unrelated plain-text events.

---

## [1.0.0] – 2026-06-23

### Added
- Initial release of **CryptLock** (formerly Ransomware Guard).
- Real-time directory monitoring via `watchdog`.
- Shannon entropy analysis for encrypted-file detection.
- Sliding-window behavioural analysis (mass rename, heavy mod, rapid delete,
  burst activity, suspicious extensions).
- Weighted risk scoring engine (NORMAL / SUSPICIOUS / RANSOMWARE bands).
- Auto-backup with timestamped, hash-deduplicated backup trees.
- Containment engine — terminates approved simulation processes only.
- Recovery engine with full report generation.
- Live auto-refreshing terminal dashboard.
- Dual structured log files (`events.log`, `incidents.log`).
- Safe ransomware simulator (`simulate_ransomware.py`) for testing.
- Full `README.md` with architecture diagrams, module reference, and Q&A.
