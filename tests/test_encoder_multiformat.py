"""Tests for DNSExfilEncoder with hex, base32, and base64 encoding schemes."""

import logging
import os
import re

import pytest

from detection.entropy import subdomain_entropy
from exfil.encoder import SUPPORTED_ENCODINGS, DNSExfilEncoder

logger = logging.getLogger(__name__)

_TEST_DOMAIN = "exfil.invalid"


def test_hex_roundtrip_binary():
    """encode/decode round-trip with hex encoding preserves 100 random bytes."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN, encoding="hex")
    data = os.urandom(100)
    assert encoder.decode(encoder.encode(data).fqdns) == data


def test_base32_roundtrip_binary():
    """encode/decode round-trip with base32 encoding preserves 100 random bytes."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN, encoding="base32")
    data = os.urandom(100)
    assert encoder.decode(encoder.encode(data).fqdns) == data


def test_base64_roundtrip_binary():
    """encode/decode round-trip with base64 encoding preserves 100 random bytes."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN, encoding="base64")
    data = os.urandom(100)
    assert encoder.decode(encoder.encode(data).fqdns) == data


def test_base32_roundtrip_text():
    """encode/decode round-trip with base32 preserves b'secret exfil data'."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN, encoding="base32")
    data = b"secret exfil data"
    assert encoder.decode(encoder.encode(data).fqdns) == data


def test_base64_roundtrip_text():
    """encode/decode round-trip with base64 preserves b'secret exfil data'."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN, encoding="base64")
    data = b"secret exfil data"
    assert encoder.decode(encoder.encode(data).fqdns) == data


def test_unsupported_encoding_raises():
    """DNSExfilEncoder raises ValueError for an unrecognised encoding name."""
    with pytest.raises(ValueError):
        DNSExfilEncoder(target_domain=_TEST_DOMAIN, encoding="base58")


def test_base32_labels_dns_safe():
    """All base32 chunk labels contain only DNS-safe characters [a-z2-7_0-9]."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN, encoding="base32")
    result = encoder.encode(os.urandom(50))
    terminator = f"done.{_TEST_DOMAIN}"
    for fqdn in result.fqdns:
        if fqdn == terminator:
            continue
        label = fqdn.split(".")[0]
        chunk = label.split("_", 2)[2]
        # base32 alphabet: a-z and 2-7; sequence prefix digits are also valid
        assert re.fullmatch(r"[a-z2-7]+", chunk), f"Unsafe chars in base32 label chunk: {chunk!r}"


def test_base64_labels_dns_safe():
    """All base64 chunk labels contain only URL-safe characters [A-Za-z0-9\\-_]."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN, encoding="base64")
    result = encoder.encode(os.urandom(50))
    terminator = f"done.{_TEST_DOMAIN}"
    for fqdn in result.fqdns:
        if fqdn == terminator:
            continue
        label = fqdn.split(".")[0]
        chunk = label.split("_", 2)[2]
        # urlsafe_b64 alphabet: A-Z, a-z, 0-9, -, _ (case preserved; base64 is case-sensitive)
        assert re.fullmatch(r"[A-Za-z0-9\-_]+", chunk), f"Unsafe chars in base64 label chunk: {chunk!r}"


def test_encode_result_carries_encoding():
    """EncodeResult.encoding reflects the scheme used by the encoder."""
    encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN, encoding="base32")
    result = encoder.encode(b"test payload")
    assert result.encoding == "base32"


def test_all_encodings_produce_valid_fqdns():
    """All supported encodings produce non-empty string FQDNs, last is the terminator."""
    data = os.urandom(50)
    for enc in SUPPORTED_ENCODINGS:
        encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN, encoding=enc)
        result = encoder.encode(data)
        assert all(isinstance(f, str) and f for f in result.fqdns), \
            f"Empty or non-string FQDN with encoding={enc}"
        assert result.fqdns[-1] == f"done.{_TEST_DOMAIN}", \
            f"Last FQDN is not terminator with encoding={enc}"


def test_base32_entropy_higher_than_hex_on_english():
    """base32 label entropy exceeds hex label entropy for a repetitive English payload."""
    data = b"hello world" * 10
    hex_encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN, encoding="hex")
    b32_encoder = DNSExfilEncoder(target_domain=_TEST_DOMAIN, encoding="base32")

    terminator = f"done.{_TEST_DOMAIN}"

    hex_result = hex_encoder.encode(data)
    hex_first_label = next(
        f.split(".")[0].split("_", 2)[2]
        for f in hex_result.fqdns
        if f != terminator
    )

    b32_result = b32_encoder.encode(data)
    b32_first_label = next(
        f.split(".")[0].split("_", 2)[2]
        for f in b32_result.fqdns
        if f != terminator
    )

    hex_entropy = subdomain_entropy(hex_first_label)
    b32_entropy = subdomain_entropy(b32_first_label)
    assert b32_entropy > hex_entropy, (
        f"Expected base32 entropy ({b32_entropy:.3f}) > hex entropy ({hex_entropy:.3f})"
    )
