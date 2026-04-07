"""Tests for detection.beacon_detector.detect_beaconing."""

import logging

import pytest

from detection.beacon_detector import BeaconResult, detect_beaconing

logger = logging.getLogger(__name__)

# Regular 0.5-second interval timestamps used across several tests.
_REGULAR_TIMESTAMPS = [0.0, 0.5, 1.0, 1.5, 2.0, 2.5]


def test_empty_list_returns_insufficient():
    """Asserts detect_beaconing([]) returns confidence='insufficient_data' and is_beacon=False."""
    result = detect_beaconing([])
    assert result.confidence == "insufficient_data"
    assert result.is_beacon is False


def test_single_timestamp_returns_insufficient():
    """Asserts a single timestamp returns confidence='insufficient_data'."""
    result = detect_beaconing([1000.0])
    assert result.confidence == "insufficient_data"
    assert result.is_beacon is False


def test_two_timestamps_returns_insufficient():
    """Asserts two timestamps (one interval) returns confidence='insufficient_data'."""
    # One interval means stdev cannot be computed — insufficient to classify.
    result = detect_beaconing([1000.0, 1001.0])
    assert result.confidence == "insufficient_data"
    assert result.is_beacon is False


def test_regular_intervals_high_confidence():
    """Asserts perfectly regular 0.5s intervals yield is_beacon=True and confidence='high'."""
    result = detect_beaconing(_REGULAR_TIMESTAMPS)
    assert result.is_beacon is True
    assert result.confidence == "high"


def test_regular_intervals_estimated_interval():
    """Asserts estimated_interval_seconds is approximately 0.5s for regular 0.5s spacing."""
    result = detect_beaconing(_REGULAR_TIMESTAMPS)
    assert abs(result.estimated_interval_seconds - 0.5) < 0.01


def test_regular_intervals_regularity_score_near_one():
    """Asserts regularity_score is > 0.95 for near-perfect interval regularity."""
    result = detect_beaconing(_REGULAR_TIMESTAMPS)
    assert result.regularity_score > 0.95


def test_randomised_intervals_low_confidence():
    """Asserts highly irregular timestamps yield is_beacon=False and confidence='low'."""
    # Large variance in gaps: 0.1, 3.4, 0.1, 6.4, 0.2 seconds
    timestamps = [0.0, 0.1, 3.5, 3.6, 10.0, 10.2]
    result = detect_beaconing(timestamps)
    assert result.is_beacon is False
    assert result.confidence == "low"


def test_unsorted_input_handled():
    """Asserts unsorted timestamps produce the same result as sorted timestamps."""
    sorted_result = detect_beaconing(_REGULAR_TIMESTAMPS)
    reversed_result = detect_beaconing(list(reversed(_REGULAR_TIMESTAMPS)))
    assert sorted_result.is_beacon == reversed_result.is_beacon
    assert sorted_result.confidence == reversed_result.confidence
    assert abs(sorted_result.estimated_interval_seconds - reversed_result.estimated_interval_seconds) < 1e-9


def test_result_is_beacon_result_type():
    """Asserts detect_beaconing returns a BeaconResult instance."""
    result = detect_beaconing(_REGULAR_TIMESTAMPS)
    assert isinstance(result, BeaconResult)


def test_medium_confidence_range():
    """Asserts timestamps with CV between 0.15 and 0.30 yield confidence='medium' and is_beacon=True."""
    # Intervals: 1.0, 1.3, 0.9, 1.3, 1.1 — moderate variance, CV in medium range.
    timestamps = [0.0, 1.0, 2.3, 3.2, 4.5, 5.6]
    result = detect_beaconing(timestamps)
    assert result.confidence == "medium"
    assert result.is_beacon is True
