# 🛡️ Ransomware Guard
### Real-Time Terminal Ransomware Detection & Response System
> **For educational and defensive security use only.**

---

## 📋 Table of Contents
1. [Overview](#overview)
2. [Project Structure](#project-structure)
3. [Architecture](#architecture)
4. [Data Flow](#data-flow)
5. [Installation](#installation)
6. [Usage](#usage)
7. [Configuration](#configuration)
8. [Safe Simulation Testing](#safe-simulation-testing)
9. [Example Terminal Output](#example-terminal-output)
10. [Module Reference](#module-reference)
11. [Interview Q&A](#interview-qa)

---

## Overview

**Ransomware Guard** is a pure-Python terminal application that monitors a directory
in real-time and automatically detects, alerts, and responds to ransomware-like behaviour.

### What it does
| Feature | Details |
|---|---|
| 📁 Real-time monitoring | Uses `watchdog` to capture create/modify/delete/rename events |
| 🔢 Shannon entropy analysis | Detects encrypted/compressed files by measuring data randomness |
| 🧠 Behaviour analysis | Sliding-window detection of mass renames, bulk mods, burst activity |
| ⚖️ Risk scoring | 0-100 weighted score driving NORMAL / SUSPICIOUS / RANSOMWARE tiers |
| 💾 Auto backup | Timestamped, hash-deduplicated backups before any response action |
| 🔫 Containment | Terminates *approved simulation processes only* |
| 🔄 Recovery | Restores files from the latest backup on demand |
| 📊 Live dashboard | Auto-refreshing stats panel in the terminal |
| 🗒️ Logging | Structured event and incident logs |
| 📄 Reports | Incident and recovery reports saved to `reports/` |

### What it does NOT do
- ❌ Create, spread, or simulate real malware
- ❌ Encrypt any files
- ❌ Target arbitrary or system processes
- ❌ Communicate over the network

---

## Project Structure

```
ransomware_guard/
├── main.py                    ← Entry point / terminal UI
├── config.py                  ← All tunable settings
├── requirements.txt
├── simulate_ransomware.py     ← Safe behavioural simulator (test use only)
│
├── detector/
│   ├── entropy.py             ← Shannon entropy analysis
│   ├── behavior.py            ← Sliding-window behaviour detection
│   ├── risk_engine.py         ← Weighted risk score calculation
│   └── monitor.py             ← Watchdog event handler + Observer lifecycle
│
├── response/
│   ├── backup_manager.py      ← Timestamped backup & restore
│   ├── containment.py         ← Orchestrates full containment workflow
│   └── recovery.py            ← File recovery + report generation
│
├── process/
│   └── process_monitor.py     ← psutil process scanner (safe targets only)
│
├── utils/
│   ├── logger.py              ← Dual-file structured logger
│   └── helpers.py             ← ANSI colours, formatting, safe I/O
│
├── logs/
│   ├── events.log             ← Every file-system event
│   └── incidents.log          ← High-risk confirmed incidents
│
├── backups/
│   └── backup_<timestamp>/    ← Timestamped backup trees
│
└── reports/
    ├── incident_report_*.txt  ← Per-incident evidence
    └── recovery_report_*.txt  ← Per-recovery summary
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        main.py                              │
│  Banner → Get Directory → Start Monitor → Event Loop        │
└──────┬──────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│               detector/monitor.py  (watchdog)               │
│  FileCreated / FileModified / FileDeleted / FileMoved       │
└──────┬──────────────────────────────────────────────────────┘
       │  every event
       ▼
┌──────────────┐   ┌──────────────┐   ┌────────────────────┐
│  behavior.py │   │  entropy.py  │   │ process_monitor.py │
│  Sliding-    │   │  Shannon     │   │  psutil scan       │
│  window      │   │  entropy     │   │  (sim procs only)  │
│  counters    │   │  score       │   │                    │
└──────┬───────┘   └──────┬───────┘   └─────────┬──────────┘
       │                  │                      │
       └──────────────────┴──────────────────────┘
                          │
                          ▼
               ┌──────────────────────┐
               │    risk_engine.py    │
               │  Weighted Score 0-100│
               └──────┬───────────────┘
                      │
          ┌───────────┴──────────────┐
          │ SUSPICIOUS (41-70)       │ RANSOMWARE (71-100)
          ▼                         ▼
     [WARNING alert]         ┌─────────────────────┐
                             │   containment.py     │
                             │  1. Backup           │
                             │  2. Save Evidence    │
                             │  3. Terminate Sim    │
                             │  4. Log Incident     │
                             └──────────────────────┘
```

---

## Data Flow

```
File Event
    │
    ▼
BehaviorAnalyzer.record_event(type, path)
    │
    ├─ Increment sliding-window counters
    │
    ▼
BehaviorAnalyzer.analyse() → BehaviorStats { flags, counts }
    │
    ├─ entropy.analyse_file_entropy(path)  →  float (0-8)
    │
    ▼
RiskEngine.evaluate(stats, entropy, proc_flag) → RiskReport { score, level, reasons }
    │
    ├── NORMAL     → log only
    ├── SUSPICIOUS → WARNING log + terminal alert
    └── RANSOMWARE → ALERT + ContainmentEngine.respond()
                          ├── BackupManager.create_backup()
                          ├── _save_evidence() → incident_report_*.txt
                          ├── ProcessMonitor.terminate_simulation_process()
                          └── log_incident()
```

---

## Installation

### Prerequisites
- Python 3.10+ (uses structural pattern matching `match/case`)
- Linux / macOS / Windows

### Steps

```bash
# 1. Navigate to the project
cd ransomware_guard

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Usage

```bash
# Start the tool
python main.py
```

On launch you will see:
1. **ASCII banner**
2. **Directory prompt** — enter the folder to monitor
3. **Live event feed** — every file event printed in colour
4. **Auto-refreshing dashboard** — statistics panel every 3 seconds
5. **Alerts / responses** — printed inline when risk rises

Press **Ctrl+C** to stop monitoring. You will then be offered the option to restore files from the latest backup.

---

## Configuration

Edit `config.py` to tune the system:

| Setting | Default | Description |
|---|---|---|
| `ENTROPY_HIGH_THRESHOLD` | `7.0` | Entropy above this → HIGH (encrypted) |
| `RISK_SCORE_NORMAL` | `40` | Score ≤ 40 → NORMAL |
| `RISK_SCORE_SUSPICIOUS` | `70` | Score 41-70 → SUSPICIOUS |
| `MASS_RENAME_THRESHOLD` | `5` | Renames in window to flag mass-rename |
| `HEAVY_MOD_THRESHOLD` | `10` | Modifications in window to flag heavy-mod |
| `BURST_WINDOW_SECONDS` | `10` | Sliding window size in seconds |
| `SUSPICIOUS_EXTENSIONS` | `.locked, .encrypted, …` | Ransomware extension list |
| `APPROVED_SIMULATION_PROCESSES` | `simulate_ransomware.py, …` | Safe-to-terminate list |
| `DASHBOARD_REFRESH_SECONDS` | `3.0` | Stats panel refresh rate |

---

## Safe Simulation Testing

Run the simulator in a second terminal **while** Ransomware Guard is monitoring the same folder.

```bash
# Terminal 1: Start Ransomware Guard
python main.py
# → Enter:  /path/to/your/test_dir

# Terminal 2: Run simulator (targets the same folder)
python simulate_ransomware.py --dir /path/to/your/test_dir --files 20 --delay 0.1
```

The simulator will:
1. Create 20 harmless `.txt` files
2. Overwrite them with high-entropy test bytes  (triggers entropy + heavy-mod detectors)
3. Rename them all to `.locked`  (triggers mass-rename + suspicious-extension detectors)

Expected Ransomware Guard output:
```
  14:23:01  [INFO    ]  📄 Created  →  document_0000.txt
  14:23:02  [INFO    ]  ✏️  Modified →  document_0001.txt
  ...
  14:23:05  [WARNING ]  Suspicious behaviour  |  Risk Score: 50/100
  14:23:05  [WARNING ]    ↳ Heavy file modifications (12 in 10s window)
  14:23:06  [ALERT   ]  🚨 POTENTIAL RANSOMWARE DETECTED  |  Risk Score: 95/100
  14:23:06  [RESPONSE]  ⚙  Initiating containment protocol…
  14:23:06  [RESPONSE]  ✔  Backup created at backups/backup_20240623_142306
  14:23:06  [RESPONSE]  ✔  Evidence saved to reports/incident_report_20240623_142306.txt
  14:23:06  [PROCESS ]  ⚠  Simulation process detected: simulate_ransomware.py (PID 12345)
  14:23:07  [RESPONSE]  ✔  Simulation process terminated: simulate_ransomware.py (PID 12345)
```

---

## Example Terminal Output

```
══════════════════════════════════════════════════════
  ██████╗  ██████╗     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ...
       RANSOMWARE GUARD  v1.0
   Real-Time Detection & Response System
══════════════════════════════════════════════════════

  Enter directory to monitor:
  (Press Ctrl+C to exit at any time)

  → /home/user/Documents

  ✔  Directory validated: /home/user/Documents
  ⚙  Starting real-time monitoring…

  ══════════════════════════════════════════════════════
  Monitoring started  —  Press Ctrl+C to stop
  ══════════════════════════════════════════════════════

  14:30:01  [INFO    ]  📄 Created   →  report.txt
  14:30:02  [INFO    ]  ✏️  Modified  →  budget.xlsx
  14:30:02  [INFO    ]  Entropy Score: 2.341  [LOW]
  14:30:05  [WARNING ]  Suspicious behaviour  |  Risk Score: 45/100
  ...

  ──────────────────────────────────────────────────────
  LIVE DASHBOARD   2024-06-23 14:30:08
  ──────────────────────────────────────────────────────
  Watching               /home/user/Documents
  Risk Score             95/100  ████████████████░░░░  [RANSOMWARE]
  Events Processed       38
  Alerts Generated       3
  Backups Created        1
  Incidents Detected     1
  Last Event             14:30:07  RENAMED: budget.xlsx.locked
  ──────────────────────────────────────────────────────
```

---

## Module Reference

### `detector/entropy.py`
| Function | Description |
|---|---|
| `calculate_entropy(data)` | Shannon entropy of raw bytes, returns 0.0-8.0 |
| `analyse_file_entropy(path)` | Reads file, returns entropy or None |
| `classify_entropy(score)` | Returns "LOW" / "MEDIUM" / "HIGH" |
| `entropy_risk_points(score)` | Returns risk score contribution |

### `detector/behavior.py`
| Method | Description |
|---|---|
| `record_event(type, path)` | Add event to sliding window |
| `analyse()` | Return BehaviorStats with active flags |

### `detector/risk_engine.py`
| Method | Description |
|---|---|
| `evaluate(stats, entropy, proc_flag)` | Returns RiskReport with score + level |

### `response/backup_manager.py`
| Method | Description |
|---|---|
| `create_backup(watch_dir)` | Timestamped backup, returns (path, files) |
| `restore_backup(backup_path, target)` | Restores files, returns (count, seconds) |
| `get_latest_backup()` | Path of most recent backup |

---

## Interview Q&A

**Q1: What is Shannon entropy and why is it useful for ransomware detection?**
> Shannon entropy measures the randomness of data. Plaintext and structured files have low entropy (3-4 bits/byte) because characters repeat. Encrypted data appears random and has high entropy (7-8 bits/byte). Since ransomware encrypts victims' files, a sudden spike in file entropy after modification is a strong behavioral signal.

**Q2: What is a sliding-window detector?**
> A sliding window discards events older than N seconds. This focuses analysis on *recent* activity rather than lifetime totals, which prevents false positives from legitimate gradual file changes and keeps detection sensitive to bursts.

**Q3: How does the risk scoring engine work?**
> Each behavioural indicator contributes a weighted number of points (e.g. mass rename = +30, high entropy = +25). Points are summed and capped at 100. Thresholds divide scores into NORMAL (0-40), SUSPICIOUS (41-70), and RANSOMWARE (71-100) bands, triggering escalating responses.

**Q4: Why is process termination limited to approved simulation processes?**
> Targeting arbitrary processes would make this tool dangerous and potentially disruptive to users and systems. By white-listing only known test/simulation script names, we ensure the containment functionality cannot be weaponised or cause collateral damage. This is also ethically and legally essential.

**Q5: How do backups prevent data loss in a real ransomware scenario?**
> Backups are created *before* any response action. If ransomware has already modified files, the backup still preserves the pre-attack state. After containment, the recovery engine restores all backed-up files to their original paths, effectively undoing the damage.

**Q6: What is watchdog and how is it used here?**
> `watchdog` is a Python library that registers OS-level file-system notification callbacks (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows). It calls our `RansomwareEventHandler` methods for every create/modify/delete/rename event without polling, making monitoring efficient and near-instantaneous.

**Q7: What improvements would you make for a production-grade system?**
> (1) Machine learning classifier on entropy + behaviour vectors. (2) Network traffic analysis for C2 communication detection. (3) Shadow copy / VSS integration on Windows. (4) Kernel-level driver hooks for deeper visibility. (5) SIEM integration (Splunk/ELK). (6) Alert deduplication and suppression rules. (7) Role-based access for the recovery/containment commands.
