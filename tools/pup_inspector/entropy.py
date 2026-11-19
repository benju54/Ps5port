"""
Entropy analysis utility for memory blocks and firmware containers.
Identifies plaintext vs compressed/encrypted blocks using Shannon entropy.
"""

from __future__ import annotations
import math
from typing import List, Tuple

ENTROPY_PLAINTEXT_THRESHOLD = 7.1
ENTROPY_HIGH_THRESHOLD = 7.85  # Near 8.0 indicates cryptographic randomness or compression


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0

    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1

    entropy = 0.0
    for count in counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def classify_entropy(entropy: float) -> str:
    """Classify the entropy level into human-readable security state."""
    if entropy < 3.5:
        return "LOW_ENTROPY_SPARSE"
    elif entropy < ENTROPY_PLAINTEXT_THRESHOLD:
        return "PLAINTEXT_CODE_OR_DATA"
    elif entropy < ENTROPY_HIGH_THRESHOLD:
        return "STRUCTURED_OR_COMPRESSED"
    else:
        return "ENCRYPTED_OR_HIGH_ENTROPY"


def scan_entropy_blocks(
    data: bytes, block_size: int = 4096
) -> List[Tuple[int, float, str]]:
    """
    Split data into fixed-size blocks and return list of (offset, entropy, classification).
    """
    results: List[Tuple[int, float, str]] = []
    total_len = len(data)

    for offset in range(0, total_len, block_size):
        chunk = data[offset : offset + block_size]
        ent = calculate_entropy(chunk)
        results.append((offset, ent, classify_entropy(ent)))

    return results
