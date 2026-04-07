# Shannon entropy calculation for DNS subdomain labels.
# Used to distinguish encoded or compressed labels from human-readable ones.

from __future__ import annotations

import logging
import math
from collections import Counter

logger = logging.getLogger(__name__)


def subdomain_entropy(label: str) -> float:
    """Calculate the Shannon entropy of a subdomain label in bits per character.

    Normal human-readable labels (e.g. 'mail', 'api', 'cdn-west-1') score
    roughly 2.5–3.5 bits. Hex-encoded data scores ~3.8–4.0 bits because the
    character distribution is near-uniform across the 16-symbol hex alphabet.

    Args:
        label: A single DNS label (the portion before the first dot).
               Empty string returns 0.0.

    Returns:
        Shannon entropy in bits per character. 0.0 for empty or single-character
        labels where entropy is undefined or zero.
    """
    if len(label) <= 1:
        return 0.0

    counts = Counter(label)
    length = len(label)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )
    logger.debug("entropy('%s') = %.4f", label, entropy)
    return entropy
