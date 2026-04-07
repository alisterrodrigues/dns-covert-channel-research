# Timing analysis for DNS query sequences.
# Detects regular beaconing patterns by measuring the coefficient of variation
# of inter-query intervals.

from __future__ import annotations

import logging
import math
import statistics
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class BeaconResult:
    """Result of a beaconing analysis over a sequence of query timestamps.

    Attributes:
        is_beacon: True if the query timing shows regular periodic intervals.
        estimated_interval_seconds: Mean interval between queries in seconds.
            0.0 if fewer than 2 timestamps were provided.
        regularity_score: Float 0.0–1.0. 1.0 means perfectly regular spacing.
            Derived from the coefficient of variation (CV = std/mean):
            score = max(0.0, 1.0 - CV). 0.0 if mean interval is 0.
        confidence: One of "high", "medium", "low", or "insufficient_data".
            high   -> CV < 0.15  (very regular, almost certainly a beacon)
            medium -> CV < 0.30  (somewhat regular, worth investigating)
            low    -> CV >= 0.30 (noisy timing, probably not a beacon)
            insufficient_data -> fewer than 3 timestamps
    """

    is_beacon: bool
    estimated_interval_seconds: float
    regularity_score: float
    confidence: str


def detect_beaconing(
    query_timestamps: list[float], tolerance: float = 0.1
) -> BeaconResult:
    """Analyse a list of Unix timestamps for regular beaconing patterns.

    Computes inter-query intervals and measures their coefficient of variation
    (CV = standard deviation / mean). Low CV indicates regular timing consistent
    with automated beaconing. High CV indicates irregular or organic timing.

    Args:
        query_timestamps: Ordered list of Unix timestamps (float seconds).
            Should be sorted ascending; unsorted input is sorted internally.
        tolerance: Currently unused. Reserved for future interval-matching
            tolerance tuning. Default 0.1.

    Returns:
        BeaconResult with is_beacon, estimated_interval_seconds,
        regularity_score, and confidence.
    """
    timestamps = sorted(query_timestamps)

    if len(timestamps) < 2:
        return BeaconResult(
            is_beacon=False,
            estimated_interval_seconds=0.0,
            regularity_score=0.0,
            confidence="insufficient_data",
        )

    intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
    mean_interval = statistics.mean(intervals)

    if len(intervals) == 1:
        return BeaconResult(
            is_beacon=False,
            estimated_interval_seconds=mean_interval,
            regularity_score=0.0,
            confidence="insufficient_data",
        )

    std_interval = statistics.stdev(intervals)

    if mean_interval == 0:
        logger.debug(
            "beaconing analysis: %d timestamps, mean_interval=%.3fs, CV=undefined, confidence=low",
            len(timestamps),
            mean_interval,
        )
        return BeaconResult(
            is_beacon=False,
            estimated_interval_seconds=0.0,
            regularity_score=0.0,
            confidence="low",
        )

    cv = std_interval / mean_interval
    regularity_score = max(0.0, 1.0 - cv)

    if cv < 0.15:
        confidence = "high"
        is_beacon = True
    elif cv < 0.30:
        confidence = "medium"
        is_beacon = True
    else:
        confidence = "low"
        is_beacon = False

    logger.debug(
        "beaconing analysis: %d timestamps, mean_interval=%.3fs, CV=%.3f, confidence=%s",
        len(timestamps),
        mean_interval,
        cv,
        confidence,
    )

    return BeaconResult(
        is_beacon=is_beacon,
        estimated_interval_seconds=mean_interval,
        regularity_score=regularity_score,
        confidence=confidence,
    )
