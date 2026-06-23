"""
detector/entropy.py
===================
Shannon Entropy Analysis Module.

Shannon entropy measures the randomness of data.
  - Plain text files → low entropy  (~3-4 bits/byte)
  - Encrypted / compressed files → high entropy (~7-8 bits/byte)

Ransomware encrypts victims' files, so high entropy after a modification
is a strong indicator of possible encryption activity.
"""

import math
from typing import Optional

import config
from utils.helpers import safe_file_read


def calculate_entropy(data: bytes) -> float:
    """
    Compute the Shannon entropy of *data* in bits per byte.

    Formula
    -------
    H = -Σ p(x) * log2(p(x))   for each unique byte value x

    Parameters
    ----------
    data : Raw bytes to analyse.

    Returns
    -------
    float in range [0.0, 8.0].
             0.0 → every byte is identical (zero randomness)
             8.0 → perfectly uniform distribution (maximum randomness)
    """
    if not data:
        return 0.0

    # Count occurrences of each byte value (0-255)
    frequency: dict[int, int] = {}
    for byte in data:
        frequency[byte] = frequency.get(byte, 0) + 1

    # Calculate probability and accumulate entropy
    total_bytes = len(data)
    entropy = 0.0
    for count in frequency.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)

    return entropy


def analyse_file_entropy(file_path: str) -> Optional[float]:
    """
    Read a file and return its Shannon entropy score.

    Parameters
    ----------
    file_path : Absolute path to the file.

    Returns
    -------
    float  – entropy score, or None if the file cannot be read.
    """
    data = safe_file_read(file_path, config.MAX_FILE_SIZE_FOR_ENTROPY)
    if data is None:
        return None
    return calculate_entropy(data)


def classify_entropy(score: float) -> str:
    """
    Map an entropy score to a human-readable classification.

    Parameters
    ----------
    score : Shannon entropy value.

    Returns
    -------
    str – "LOW" | "MEDIUM" | "HIGH"
    """
    if score < config.ENTROPY_LOW_THRESHOLD:
        return "LOW"
    if score < config.ENTROPY_HIGH_THRESHOLD:
        return "MEDIUM"
    return "HIGH"


def entropy_risk_points(score: float) -> int:
    """
    Convert an entropy classification to a risk-score contribution.

    Returns
    -------
    int – 0, 12, or RISK_WEIGHT_HIGH_ENTROPY from config.
    """
    classification = classify_entropy(score)
    if classification == "HIGH":
        return config.RISK_WEIGHT_HIGH_ENTROPY
    if classification == "MEDIUM":
        return config.RISK_WEIGHT_HIGH_ENTROPY // 2
    return 0
