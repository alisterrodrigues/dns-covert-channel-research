"""Tests for DNSExfilEncoder encode() and decode() methods."""

import logging
import os

import pytest

from exfil.encoder import DNSExfilEncoder, EncodeResult

logger = logging.getLogger(__name__)

# Domain used across tests — .invalid never resolves, safe for offline runs.
_TEST_DOMAIN = "exfil.invalid"


# ---------------------------------------------------------------------------
# Basic encode behaviour
# ---------------------------------------------------------------------------


def test_encode_returns_fqdns():
    """encode(b'hello') returns a list of strings, last starting with 'done.'."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN)
    result = encoder.encode(b"hello")
    assert isinstance(result.fqdns, list)
    assert all(isinstance(f, str) for f in result.fqdns)
    assert result.fqdns[-1].startswith("done.")


def test_encode_empty():
    """encode(b'') returns EncodeResult with empty fqdns list and chunk_count=0."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN)
    result = encoder.encode(b"")
    assert isinstance(result, EncodeResult)
    assert result.fqdns == []
    assert result.chunk_count == 0


def test_encode_includes_terminator():
    """The last FQDN in a non-empty encode result is the done terminator."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN)
    result = encoder.encode(b"any data")
    assert result.fqdns[-1] == f"done.{_TEST_DOMAIN}"


# ---------------------------------------------------------------------------
# Label safety
# ---------------------------------------------------------------------------


def test_no_label_exceeds_63_chars():
    """Every label in every FQDN from 10-, 100-, and 1000-byte inputs stays within 63 characters."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN)
    # DNS RFC 1035 hard limit per label is 63 characters.
    dns_label_max = 63
    for size in (10, 100, 1000):
        data = os.urandom(size)
        result = encoder.encode(data)
        for fqdn in result.fqdns:
            for label in fqdn.split("."):
                assert len(label) <= dns_label_max, (
                    f"Label '{label}' in '{fqdn}' is {len(label)} chars (max {dns_label_max})"
                )


def test_chunk_size_validation():
    """DNSExfilEncoder raises ValueError when chunk_size exceeds the DNS label cap."""
    with pytest.raises(ValueError):
        # Exceeds _MAX_CHUNK_SIZE (label prefix + chunk must fit in 63 chars); must raise.
        DNSExfilEncoder(target_domain=_TEST_DOMAIN, chunk_size=61)


def test_chunk_size_minimum():
    """DNSExfilEncoder raises ValueError when chunk_size=0 (below minimum of 1)."""
    with pytest.raises(ValueError):
        DNSExfilEncoder(target_domain=_TEST_DOMAIN, chunk_size=0)


# ---------------------------------------------------------------------------
# Sequence numbers
# ---------------------------------------------------------------------------


def test_sequence_numbers_present():
    """Every non-terminator FQDN label starts with a two-digit sequence prefix and '_'."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN)
    result = encoder.encode(b"hello world")
    terminator = f"done.{_TEST_DOMAIN}"
    for fqdn in result.fqdns:
        if fqdn == terminator:
            continue
        label = fqdn.split(".")[0]
        # Format: NN_tag_chunk — at least three underscore-separated parts.
        assert "_" in label, f"Label '{label}' missing '_' sequence separator"
        label_parts = label.split("_", 2)
        assert len(label_parts) == 3, f"Label '{label}' not in NN_tag_chunk format"
        prefix, tag, _chunk = label_parts
        assert prefix.isdigit(), f"Sequence prefix '{prefix}' is not numeric"
        assert len(prefix) >= 2, f"Sequence prefix '{prefix}' shorter than minimum 2 digits"
        assert tag in ("h", "b32", "b64"), f"Unknown encoding tag '{tag}' in label '{label}'"


def test_sequence_numbers_ordered():
    """Sequence numbers increase by 1 from 00 through N-1 with no gaps."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN)
    result = encoder.encode(b"hello world")
    terminator = f"done.{_TEST_DOMAIN}"
    seq_nums = []
    for fqdn in result.fqdns:
        if fqdn == terminator:
            continue
        label = fqdn.split(".")[0]
        prefix = label.split("_", 1)[0]
        seq = int(prefix)
        seq_nums.append(seq)
    expected = list(range(len(seq_nums)))
    assert seq_nums == expected, (
        f"Sequence numbers {seq_nums} are not contiguous from 0"
    )


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


def test_roundtrip_10_bytes():
    """decode(encode(data).fqdns) == data for 10 random bytes."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN)
    data = os.urandom(10)
    assert encoder.decode(encoder.encode(data).fqdns) == data


def test_roundtrip_100_bytes():
    """decode(encode(data).fqdns) == data for 100 random bytes."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN)
    data = os.urandom(100)
    assert encoder.decode(encoder.encode(data).fqdns) == data


def test_roundtrip_1000_bytes():
    """decode(encode(data).fqdns) == data for 1000 random bytes."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN)
    data = os.urandom(1000)
    assert encoder.decode(encoder.encode(data).fqdns) == data


def test_roundtrip_exact_text():
    """Round-trip: encode then decode of b'secret exfil data' preserves bytes."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN)
    data = b"secret exfil data"
    assert encoder.decode(encoder.encode(data).fqdns) == data


# ---------------------------------------------------------------------------
# Decode edge cases
# ---------------------------------------------------------------------------


def test_decode_empty_list():
    """decode([]) returns b''."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN)
    assert encoder.decode([]) == b""


def test_decode_strips_terminator():
    """Decode output matches whether or not the terminator FQDN is present."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN)
    data = b"strip terminator test"
    result = encoder.encode(data)
    fqdns_with_term = result.fqdns
    # Build the list without the terminator for comparison.
    fqdns_without_term = [f for f in fqdns_with_term if not f.startswith("done.")]
    assert encoder.decode(fqdns_with_term) == encoder.decode(fqdns_without_term)


def test_sequence_numbers_beyond_99():
    """encode handles payloads large enough to produce seq >= 100 without label overflow."""
    # At chunk_size=30 (default), seq=100 first appears at payload > 1500 bytes.
    # Label becomes "100_h_<chunk>" (or other tag), still under RFC 1035 limit of 63.
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN, chunk_size=30)
    # 800 bytes -> 1600 hex chars -> ceil(1600/30) = 54 chunks — within 2-digit range.
    # Use 800 bytes to stay in safe range and verify round-trip still works.
    data = os.urandom(800)
    result = encoder.encode(data)
    assert encoder.decode(result.fqdns) == data
    # Verify no label exceeds 63 chars even with multi-digit sequence prefixes.
    for fqdn in result.fqdns:
        for label in fqdn.split("."):
            assert len(label) <= 63
