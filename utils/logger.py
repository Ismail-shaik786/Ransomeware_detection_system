"""
utils/logger.py
===============
Centralised structured logging for Ransomware Guard.
Creates two log files:
  - events.log   : every file-system event
  - incidents.log: confirmed high-risk / ransomware incidents
"""

import logging
import os
from datetime import datetime
from typing import Optional

import config


def _ensure_dirs() -> None:
    """Create log and report directories if they do not already exist."""
    os.makedirs(config.LOG_DIR, exist_ok=True)
    os.makedirs(config.REPORT_DIR, exist_ok=True)
    os.makedirs(config.BACKUP_DIR, exist_ok=True)


def _build_formatter() -> logging.Formatter:
    """Return a consistent log-line formatter."""
    return logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def get_event_logger() -> logging.Logger:
    """
    Return (or create) the event logger that writes to events.log.

    Returns
    -------
    logging.Logger
    """
    _ensure_dirs()
    logger = logging.getLogger("rg.events")
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(config.LOG_EVENTS_FILE)
        fh.setFormatter(_build_formatter())
        logger.addHandler(fh)
    return logger


def get_incident_logger() -> logging.Logger:
    """
    Return (or create) the incident logger that writes to incidents.log.

    Returns
    -------
    logging.Logger
    """
    _ensure_dirs()
    logger = logging.getLogger("rg.incidents")
    if not logger.handlers:
        logger.setLevel(logging.WARNING)
        fh = logging.FileHandler(config.LOG_INCIDENTS_FILE)
        fh.setFormatter(_build_formatter())
        logger.addHandler(fh)
    return logger


def log_event(
    event_type: str,
    message: str,
    entropy: Optional[float] = None,
    risk_score: Optional[int] = None,
) -> None:
    """
    Write a structured entry to events.log.

    Parameters
    ----------
    event_type  : Category label, e.g. "FILE_MODIFIED".
    message     : Human-readable description.
    entropy     : Shannon entropy value if available.
    risk_score  : Current aggregate risk score if available.
    """
    logger = get_event_logger()
    extra = ""
    if entropy is not None:
        extra += f" | entropy={entropy:.4f}"
    if risk_score is not None:
        extra += f" | risk={risk_score}"
    logger.info("[%s] %s%s", event_type, message, extra)


def log_incident(
    reason: str,
    risk_score: int,
    files_affected: list,
    actions_taken: list,
) -> None:
    """
    Write a high-priority entry to incidents.log.

    Parameters
    ----------
    reason         : Detection reason summary.
    risk_score     : Final score that triggered this incident.
    files_affected : List of file paths involved.
    actions_taken  : List of response actions performed.
    """
    logger = get_incident_logger()
    logger.warning(
        "INCIDENT | reason=%s | score=%d | files=%s | actions=%s",
        reason,
        risk_score,
        files_affected,
        actions_taken,
    )
