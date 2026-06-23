"""
utils/helpers.py
================
Miscellaneous utility functions used across the project.
"""

import os
import shutil
from datetime import datetime
from typing import Optional


def format_bytes(num_bytes: int) -> str:
    """
    Convert a raw byte count into a human-readable string.

    Parameters
    ----------
    num_bytes : Raw size in bytes.

    Returns
    -------
    str  e.g. "1.23 MB"
    """
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:6.2f} {unit}"
        num_bytes /= 1024.0  # type: ignore[assignment]
    return f"{num_bytes:.2f} PB"


def timestamp_str() -> str:
    """Return the current local time as a compact string, e.g. '20240623_143021'."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def readable_timestamp() -> str:
    """Return a human-readable timestamp, e.g. '2024-06-23 14:30:21'."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def safe_file_read(path: str, max_bytes: int = 10 * 1024 * 1024) -> Optional[bytes]:
    """
    Read up to *max_bytes* from a file without raising on error.

    Parameters
    ----------
    path      : Absolute path to the file.
    max_bytes : Maximum bytes to read (default 10 MB).

    Returns
    -------
    bytes or None if the file cannot be read.
    """
    try:
        with open(path, "rb") as fh:
            return fh.read(max_bytes)
    except (OSError, PermissionError):
        return None


def ensure_dir(path: str) -> None:
    """Create *path* (and all parents) if it does not already exist."""
    os.makedirs(path, exist_ok=True)


def file_extension(path: str) -> str:
    """Return the lower-cased file extension of *path*, e.g. '.txt'."""
    return os.path.splitext(path)[1].lower()


def count_files(directory: str) -> int:
    """
    Count all files recursively inside *directory*.

    Returns 0 if the directory does not exist or cannot be read.
    """
    total = 0
    try:
        for _, _, files in os.walk(directory):
            total += len(files)
    except OSError:
        pass
    return total


def colored(text: str, color_code: str) -> str:
    """
    Wrap *text* in an ANSI colour escape sequence.

    Parameters
    ----------
    text       : The string to colour.
    color_code : ANSI code, e.g. "91" for bright-red.

    Returns
    -------
    str – ANSI-coloured string (resets after text).
    """
    return f"\033[{color_code}m{text}\033[0m"


# Convenience colour helpers
def red(t: str) -> str:
    return colored(t, "91")


def yellow(t: str) -> str:
    return colored(t, "93")


def green(t: str) -> str:
    return colored(t, "92")


def cyan(t: str) -> str:
    return colored(t, "96")


def magenta(t: str) -> str:
    return colored(t, "95")


def bold(t: str) -> str:
    return colored(t, "1")


def dim(t: str) -> str:
    return colored(t, "2")
