"""
main.py  –  Ransomware Guard
============================
Entry point.  Run with:

    python main.py

Workflow
--------
1. Show startup banner.
2. Ask user for directory to monitor.
3. Validate directory.
4. Start real-time monitoring (watchdog).
5. Display live event feed + periodic dashboard refresh.
6. Detect ransomware-like behaviour via risk engine.
7. Auto-backup before containment.
8. Terminate approved simulation processes when risk > RANSOMWARE threshold.
9. Generate logs and incident reports.
10. Offer manual recovery on exit.
"""

import os
import sys
import threading
import time
from typing import List

import config
from detector.monitor import DirectoryMonitor
from detector.risk_engine import RiskReport
from process.process_monitor import ProcessMonitor
from response.backup_manager import BackupManager
from response.containment import ContainmentEngine
from response.recovery import RecoveryEngine
from utils import logger as log_module
from utils.helpers import (
    bold,
    cyan,
    dim,
    green,
    magenta,
    readable_timestamp,
    red,
    yellow,
)


# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL STATE  (thread-safe via locks where needed)
# ─────────────────────────────────────────────────────────────────────────────

class AppState:
    """Shared mutable state for the running application."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.events_processed: int = 0
        self.alerts_generated: int = 0
        self.backups_created: int = 0
        self.incidents_detected: int = 0
        self.current_risk_score: int = 0
        self.current_risk_level: str = "NORMAL"
        self.last_event: str = ""
        self.last_event_time: str = ""
        self.running: bool = True
        self.containment_in_progress: bool = False
        self.last_alert_time: float = 0.0    # epoch – debounce containment
        self.watch_dir: str = ""


STATE = AppState()


# ─────────────────────────────────────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────────────────────────────────────

BANNER = f"""
{cyan('=' * 70)}
{cyan('  ██████╗ ██████╗ ██╗   ██╗██████╗ ████████╗██╗      ██████╗  ██████╗██╗  ██╗')}
{cyan('  ██╔════╝██╔══██╗ ╚██╗██╔╝██╔══██╗╚══██╔══╝██║     ██╔═══██╗██╔════╝██║ ██╔╝')}
{cyan('  ██║     ██████╔╝  ╚███╔╝ ██████╔╝   ██║   ██║     ██║   ██║██║     █████╔╝ ')}
{cyan('  ██║     ██╔══██╗  ██╔    ██╔═══╝    ██║   ██║     ██║   ██║██║     ██╔═██╗ ')}
{cyan('  ╚██████╗██║  ██║ ██╔╝    ██║        ██║   ███████╗╚██████╔╝╚██████╗██║  ██╗')}
{cyan('   ╚═════╝╚═╝  ╚═╝ ╚═╝     ╚═╝        ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝')}
{cyan('=' * 70)}
{bold(cyan('                  C R Y P T L O C K   v1.0'))}
{dim('         Real-Time Ransomware Detection & Response System')}
{cyan('-' * 70)}
{dim('   Crypt: detects encryption attacks  |  Lock: stops them cold')}
{cyan('=' * 70)}
{dim('         ⚠  For educational and defensive security use only')}
{cyan('=' * 70)}
{dim('                        Developed by  ')}{bold(magenta('ismail-shaik'))}
{cyan('=' * 70)}
"""


def _prefix(tag: str) -> str:
    """Return a coloured log-line prefix for a given tag."""
    colour_map = {
        "INFO":     dim,
        "WARNING":  yellow,
        "ALERT":    red,
        "RESPONSE": green,
        "PROCESS":  magenta,
        "RECOVERY": cyan,
        "ERROR":    red,
    }
    fn = colour_map.get(tag, dim)
    return fn(f"[{tag:<8}]")


def _log(tag: str, message: str) -> None:
    """Print a formatted log line with timestamp."""
    ts = time.strftime("%H:%M:%S")
    print(f"  {dim(ts)}  {_prefix(tag)}  {message}")


def _risk_colour(level: str, text: str) -> str:
    """Colour text based on risk level."""
    match level:
        case "RANSOMWARE":
            return red(text)
        case "SUSPICIOUS":
            return yellow(text)
        case _:
            return green(text)


def _score_bar(score: int) -> str:
    """Render a mini ASCII progress bar for the risk score."""
    filled = score // 5      # 0-20 blocks
    bar = "█" * filled + "░" * (20 - filled)
    colour = red if score > 70 else (yellow if score > 40 else green)
    return colour(bar)


# Number of lines the dashboard occupies (used for in-place redraw)
_DASHBOARD_LINES: int = 12
_dashboard_drawn: bool = False   # True after the first render


def _dashboard_lines(watch_dir: str) -> list:
    """Build the dashboard as a list of plain strings (no trailing newline)."""
    with STATE.lock:
        score = STATE.current_risk_score
        level = STATE.current_risk_level
        events = STATE.events_processed
        alerts = STATE.alerts_generated
        backups = STATE.backups_created
        incidents = STATE.incidents_detected
        last_ev = STATE.last_event
        last_time = STATE.last_event_time

    rows = [
        f"  {cyan('─' * 54)}",
        f"  {bold('LIVE DASHBOARD')}   {dim(readable_timestamp())}   "
        f"{dim('(auto-updates every ' + str(int(config.DASHBOARD_REFRESH_SECONDS)) + 's)')}",
        f"  {cyan('─' * 54)}",
        f"  {'Watching':<22}  {dim(watch_dir[:50])}",
        f"  {'Risk Score':<22}  {_risk_colour(level, str(score) + '/100')}  "
        f"{_score_bar(score)}  {_risk_colour(level, '[' + level + ']')}",
        f"  {'Events Processed':<22}  {cyan(str(events))}",
        f"  {'Alerts Generated':<22}  {yellow(str(alerts))}",
        f"  {'Backups Created':<22}  {green(str(backups))}",
        f"  {'Incidents Detected':<22}  {red(str(incidents))}",
        f"  {'Last Event':<22}  {dim(last_time)}  {last_ev[:40] if last_ev else dim('—')}",
        f"  {cyan('─' * 54)}",
        "",   # blank separator between dashboard and event feed
    ]
    return rows


def _draw_dashboard(watch_dir: str) -> None:
    """
    Render the dashboard.

    • First call  → just print the lines (no cursor movement needed).
    • Subsequent  → move cursor up _DASHBOARD_LINES rows, then overwrite
                    each line in-place so the dashboard never scrolls.
    """
    global _dashboard_drawn

    rows = _dashboard_lines(watch_dir)

    if _dashboard_drawn:
        # Move cursor up to the top of the dashboard block
        sys.stdout.write(f"\033[{_DASHBOARD_LINES}A")

    for row in rows:
        # Clear the current terminal line, then print the new content
        sys.stdout.write(f"\r\033[K{row}\n")

    sys.stdout.flush()
    _dashboard_drawn = True


# ─────────────────────────────────────────────────────────────────────────────
# CALLBACKS  (called from watchdog thread)
# ─────────────────────────────────────────────────────────────────────────────

def _on_event(event_type: str, path: str) -> None:
    """Called for every file-system event."""
    with STATE.lock:
        STATE.events_processed += 1
        STATE.last_event = f"{event_type}: {os.path.basename(path)}"
        STATE.last_event_time = time.strftime("%H:%M:%S")

    icon_map = {
        "CREATED":  "📄 Created ",
        "MODIFIED": "✏️  Modified",
        "DELETED":  "🗑️  Deleted ",
        "RENAMED":  "🔀 Renamed ",
    }
    label = icon_map.get(event_type, event_type)
    _log("INFO", f"{label}  →  {dim(os.path.basename(path))}")


def _on_alert(report: RiskReport, affected_file: str) -> None:
    """Called when risk level is SUSPICIOUS or RANSOMWARE."""
    with STATE.lock:
        STATE.current_risk_score = report.score
        STATE.current_risk_level = report.level
        STATE.alerts_generated += 1
        last_alert = STATE.last_alert_time
        in_progress = STATE.containment_in_progress

    # Print entropy info
    _log(
        "INFO",
        f"Entropy Score: {report.entropy_score:.3f}  "
        f"[{report.entropy_classification}]"
    )

    if report.level == "SUSPICIOUS":
        _log("WARNING", _risk_colour("SUSPICIOUS",
             f"Suspicious behaviour  |  Risk Score: {report.score}/100"))
        for reason in report.reasons:
            _log("WARNING", f"  ↳ {reason}")

    elif report.level == "RANSOMWARE":
        now = time.time()
        _log("ALERT", red(
            f"🚨 POTENTIAL RANSOMWARE DETECTED  |  Risk Score: {report.score}/100"
        ))
        for reason in report.reasons:
            _log("ALERT", f"  ↳ {reason}")

        # Debounce: only trigger containment every 15 seconds
        if not in_progress and (now - last_alert) > 15:
            with STATE.lock:
                STATE.containment_in_progress = True
                STATE.last_alert_time = now
            threading.Thread(
                target=_run_containment,
                args=(report, affected_file),
                daemon=True,
            ).start()


def _run_containment(report: RiskReport, affected_file: str) -> None:
    """Execute containment in a background thread (non-blocking)."""
    try:
        _log("RESPONSE", yellow("⚙  Initiating containment protocol…"))
        engine = ContainmentEngine(STATE.watch_dir)
        actions = engine.respond(report, affected_file)

        with STATE.lock:
            STATE.incidents_detected += 1
            STATE.backups_created += 1

        for action in actions:
            _log("RESPONSE", green(f"✔  {action}"))

        log_module.log_event(
            "CONTAINMENT_COMPLETE",
            f"Risk={report.score} | {len(actions)} action(s) taken",
        )
    finally:
        with STATE.lock:
            STATE.containment_in_progress = False


# ─────────────────────────────────────────────────────────────────────────────
# BACKGROUND THREADS
# ─────────────────────────────────────────────────────────────────────────────

def _dashboard_loop(watch_dir: str) -> None:
    """Periodically redraw the in-place live statistics dashboard."""
    # Print the dashboard once immediately, then refresh on schedule
    _draw_dashboard(watch_dir)
    while STATE.running:
        time.sleep(config.DASHBOARD_REFRESH_SECONDS)
        _draw_dashboard(watch_dir)


def _process_monitor_loop(monitor: DirectoryMonitor) -> None:
    """Periodically scan processes and relay flag to the directory monitor."""
    pm = ProcessMonitor()
    while STATE.running:
        sim_running = pm.any_simulation_running()
        monitor.update_process_flag(sim_running)
        if sim_running:
            flagged = pm.scan()
            for proc in flagged:
                if proc.is_simulation:
                    _log("PROCESS", yellow(
                        f"⚠  Simulation process detected: {proc.name} "
                        f"(PID {proc.pid})  CPU={proc.cpu_percent:.1f}%"
                    ))
        time.sleep(5)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def _ask_for_directory() -> str:
    """Prompt user for a directory and validate it exists."""
    print(cyan("\n  Enter directory to monitor:"))
    print(dim("  (Press Ctrl+C to exit at any time)\n"))
    while True:
        try:
            path = input("  → ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Exiting.")
            sys.exit(0)

        path = os.path.expanduser(path)
        if os.path.isdir(path):
            return os.path.abspath(path)

        print(red(f"\n  ✖  '{path}' is not a valid directory. Please try again.\n"))


def _offer_recovery() -> None:
    """After monitoring ends, ask user if they want to restore from backup."""
    bm = BackupManager()
    backups = bm.list_backups()
    if not backups:
        print(dim("\n  No backups available for recovery."))
        return

    print(f"\n  {cyan('Available backups:')}")
    for i, bp in enumerate(backups, 1):
        print(f"  {dim(str(i))}. {bp}")

    print("\n  Restore files from latest backup? [y/N] ", end="", flush=True)
    try:
        choice = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        return

    if choice == "y":
        engine = RecoveryEngine(STATE.watch_dir)
        _log("RECOVERY", cyan("⟳  Running recovery…"))
        success, report_path = engine.recover()
        if success:
            _log("RECOVERY", green(f"✔  Recovery complete.  Report: {report_path}"))
        else:
            _log("ERROR", red(f"✖  Recovery failed.    Report: {report_path}"))


def main() -> None:
    """Application entry point."""
    # ── Banner ────────────────────────────────────────────────────────────────
    print(BANNER)

    # ── Ensure output dirs ────────────────────────────────────────────────────
    for d in (config.BACKUP_DIR, config.LOG_DIR, config.REPORT_DIR):
        os.makedirs(d, exist_ok=True)

    # ── Get target directory ──────────────────────────────────────────────────
    watch_dir = _ask_for_directory()
    STATE.watch_dir = watch_dir

    print(f"\n  {green('✔')}  Directory validated: {bold(watch_dir)}")
    print(f"  {cyan('⚙')}  Starting real-time monitoring…\n")
    print(cyan("  " + "═" * 54))
    print(f"  {bold('Monitoring started')}"
          f"  —  {dim('Press Ctrl+C to stop')}")
    print(cyan("  " + "═" * 54 + "\n"))

    log_module.log_event("MONITOR_START", f"Watching: {watch_dir}")

    # ── Start watchdog ────────────────────────────────────────────────────────
    monitor = DirectoryMonitor(watch_dir, _on_alert, _on_event)
    monitor.start()

    # ── Start background threads ──────────────────────────────────────────────
    threading.Thread(
        target=_dashboard_loop, args=(watch_dir,), daemon=True
    ).start()

    threading.Thread(
        target=_process_monitor_loop, args=(monitor,), daemon=True
    ).start()

    # ── Block main thread (wait for Ctrl+C) ───────────────────────────────────
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    # ── Graceful shutdown ─────────────────────────────────────────────────────
    print(f"\n\n  {yellow('⚠')}  Stopping monitoring…")
    STATE.running = False
    monitor.stop()

    log_module.log_event("MONITOR_STOP", f"Stopped watching: {watch_dir}")
    _draw_dashboard(watch_dir)

    # ── Offer recovery ────────────────────────────────────────────────────────
    _offer_recovery()

    print(f"\n  {cyan('Logs   →')} {config.LOG_DIR}")
    print(f"  {cyan('Reports→')} {config.REPORT_DIR}")
    print(f"  {cyan('Backups→')} {config.BACKUP_DIR}")
    print(f"\n  {dim('Ransomware Guard exited cleanly.')}\n")


if __name__ == "__main__":
    main()
