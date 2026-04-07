"""Tests for detection.entropy.subdomain_entropy."""

import logging

import pytest

from detection.entropy import subdomain_entropy

logger = logging.getLogger(__name__)


def test_empty_string_returns_zero():
    """Asserts subdomain_entropy('') returns 0.0."""
    assert subdomain_entropy("") == 0.0


def test_single_char_returns_zero():
    """Asserts subdomain_entropy('a') returns 0.0."""
    assert subdomain_entropy("a") == 0.0


def test_uniform_string_returns_zero():
    """Asserts a string of repeated identical characters has entropy 0.0."""
    assert subdomain_entropy("aaaaaaa") == 0.0


def test_hex_encoded_entropy_high():
    """Asserts hex-encoded label entropy exceeds 3.5 bits."""
    # All 16 hex symbols each appearing twice — uniform distribution, entropy = 4.0 bits.
    assert subdomain_entropy("0123456789abcdef0123456789abcdef") > 3.5


def test_human_readable_entropy_low():
    """Asserts 'www' label entropy is below 3.0 bits."""
    assert subdomain_entropy("www") < 3.0


def test_human_readable_entropy_low_2():
    """Asserts 'mail' label entropy is below 3.0 bits."""
    assert subdomain_entropy("mail") < 3.0


def test_hex_scores_higher_than_readable():
    """Asserts hex-encoded label scores higher entropy than an equivalent human-readable label."""
    # deadbeef1234567890abcdef spans the full hex alphabet -> ~3.8 bits vs mailserver ~2.9 bits.
    assert subdomain_entropy("deadbeef1234567890abcdef") > subdomain_entropy("mailserver")


def test_two_char_alphabet_entropy():
    """Asserts a binary-alphabet string returns entropy approximately 1.0 bits."""
    result = subdomain_entropy("ababab")
    assert abs(result - 1.0) < 0.01


def test_return_type_is_float():
    """Asserts subdomain_entropy always returns a float."""
    assert isinstance(subdomain_entropy(""), float)
    assert isinstance(subdomain_entropy("a"), float)
    assert isinstance(subdomain_entropy("hello"), float)
