"""Tests for detection.pcap_analyzer."""

import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from detection.beacon_detector import BeaconResult
from detection.pcap_analyzer import (
    HIGH_ENTROPY_THRESHOLD,
    HIGH_VOLUME_THRESHOLD,
    LONG_LABEL_THRESHOLD,
    DnsQuery,
    SuspiciousHost,
    analyze,
    extract_subdomain_label,
    parse_zeek_dns_log,
    run,
)

logger = logging.getLogger(__name__)

# 27-char hex-prefixed label: exceeds both the length threshold (20) and the
# entropy threshold (3.5 bits) — sufficient to produce confidence="high".
_HIGH_ENTROPY_LABEL = "00_deadbeef1234567890abcdef"

# 16-char pure hex label: exceeds the entropy threshold but not the length
# threshold — produces confidence="medium" (one signal, not both).
_MEDIUM_ENTROPY_LABEL = "cafe0123456789ab"


def _make_queries(label: str, domain: str, count: int, interval: float = 0.5) -> list[DnsQuery]:
    """Return a list of synthetic DnsQuery objects with evenly spaced timestamps."""
    fqdn = f"{label}.{domain}"
    return [
        DnsQuery(timestamp=float(i) * interval, queried_name=fqdn, src_ip="10.0.0.1")
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# extract_subdomain_label
# ---------------------------------------------------------------------------


def test_extract_subdomain_label_basic():
    """Leftmost label is returned after stripping the base domain."""
    result = extract_subdomain_label("00_68656c6c6f.exfil.invalid", "exfil.invalid")
    assert result == "00_68656c6c6f"


def test_extract_subdomain_label_no_subdomain():
    """Empty string when the FQDN equals the base domain."""
    result = extract_subdomain_label("exfil.invalid", "exfil.invalid")
    assert result == ""


def test_extract_subdomain_label_strips_trailing_dots():
    """Trailing dots on either argument do not affect the result."""
    result = extract_subdomain_label("00_abc.exfil.invalid.", "exfil.invalid.")
    assert result == "00_abc"


# ---------------------------------------------------------------------------
# analyze — empty input
# ---------------------------------------------------------------------------


def test_analyze_empty_returns_empty():
    """analyze([]) returns an empty list."""
    assert analyze([]) == []


# ---------------------------------------------------------------------------
# analyze — high entropy / confidence
# ---------------------------------------------------------------------------


def test_analyze_flags_high_entropy_domain():
    """High-entropy, long subdomain labels produce a flagged domain in results."""
    queries = _make_queries(_HIGH_ENTROPY_LABEL, "exfil.invalid", count=10)
    results = analyze(queries)
    domains = [r.domain for r in results]
    assert "exfil.invalid" in domains


def test_analyze_confidence_high_for_encoded_data():
    """confidence='high' when both entropy and length thresholds are exceeded."""
    queries = _make_queries(_HIGH_ENTROPY_LABEL, "exfil.invalid", count=10)
    results = analyze(queries)
    match = next(r for r in results if r.domain == "exfil.invalid")
    assert match.confidence == "high"


# ---------------------------------------------------------------------------
# analyze — normal traffic not flagged
# ---------------------------------------------------------------------------


def test_analyze_normal_traffic_not_flagged():
    """Short, low-entropy labels with low volume and irregular timing are not flagged."""
    # 'www' is 3 chars, very low entropy — well below both thresholds.
    # Irregular timestamps ensure no beacon signal fires alongside the low-entropy labels.
    timestamps = [0.0, 1.3, 5.7, 8.1, 20.4]
    queries = [
        DnsQuery(timestamp=t, queried_name="www.google.com", src_ip="10.0.0.1")
        for t in timestamps
    ]
    assert analyze(queries) == []


# ---------------------------------------------------------------------------
# analyze — signals list
# ---------------------------------------------------------------------------


def test_analyze_signals_populated():
    """Signals list is non-empty for a flagged domain."""
    queries = _make_queries(_HIGH_ENTROPY_LABEL, "exfil.invalid", count=10)
    results = analyze(queries)
    match = next(r for r in results if r.domain == "exfil.invalid")
    assert len(match.signals) >= 1


# ---------------------------------------------------------------------------
# analyze — sorting
# ---------------------------------------------------------------------------


def test_analyze_sorted_by_entropy_descending():
    """Results are sorted by avg_entropy from highest to lowest."""
    high_queries = _make_queries(_HIGH_ENTROPY_LABEL, "exfil.invalid", count=10)
    medium_queries = _make_queries(_MEDIUM_ENTROPY_LABEL, "suspicious.net", count=5)
    results = analyze(high_queries + medium_queries)
    assert len(results) >= 2
    entropies = [r.avg_entropy for r in results]
    assert entropies == sorted(entropies, reverse=True)


# ---------------------------------------------------------------------------
# analyze — terminator label skipped
# ---------------------------------------------------------------------------


def test_analyze_skips_done_label():
    """'done' terminator labels do not inflate entropy or length statistics."""
    data_queries = _make_queries(_HIGH_ENTROPY_LABEL, "exfil.invalid", count=10)
    # Add a terminator query — should be excluded from stats.
    done_query = DnsQuery(
        timestamp=5.0, queried_name="done.exfil.invalid", src_ip="10.0.0.1"
    )
    with_done = analyze(data_queries + [done_query])
    without_done = analyze(data_queries)

    assert len(with_done) >= 1
    assert len(without_done) >= 1

    match_with = next(r for r in with_done if r.domain == "exfil.invalid")
    match_without = next(r for r in without_done if r.domain == "exfil.invalid")
    assert abs(match_with.avg_entropy - match_without.avg_entropy) < 1e-9


# ---------------------------------------------------------------------------
# analyze — beacon_result attached
# ---------------------------------------------------------------------------


def test_analyze_beacon_result_attached():
    """beacon_result on a flagged SuspiciousHost is a BeaconResult instance."""
    queries = _make_queries(_HIGH_ENTROPY_LABEL, "exfil.invalid", count=10)
    results = analyze(queries)
    match = next(r for r in results if r.domain == "exfil.invalid")
    assert isinstance(match.beacon_result, BeaconResult)


# ---------------------------------------------------------------------------
# parse_zeek_dns_log
# ---------------------------------------------------------------------------

# Minimal Zeek dns.log header and data rows.
_ZEEK_LOG_CONTENT = (
    "#separator \\x09\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery\n"
    "1700000000.0\tCxyz1\t192.168.1.10\t54321\t8.8.8.8\t53\tudp\t1234\t0.001\texfil.invalid\n"
    "1700000001.0\tCxyz2\t192.168.1.10\t54322\t8.8.8.8\t53\tudp\t1235\t0.001\t00_abc.exfil.invalid\n"
    "1700000002.0\tCxyz3\t192.168.1.11\t54323\t8.8.8.8\t53\tudp\t1236\t0.001\tdone.exfil.invalid\n"
)


def test_parse_zeek_dns_log_basic(tmp_path):
    """parse_zeek_dns_log returns one DnsQuery per valid data row."""
    log_file = tmp_path / "dns.log"
    log_file.write_text(_ZEEK_LOG_CONTENT)
    results = parse_zeek_dns_log(log_file)
    assert len(results) == 3
    assert results[0].src_ip == "192.168.1.10"
    assert results[0].queried_name == "exfil.invalid"
    assert results[0].timestamp == 1700000000.0


def test_parse_zeek_dns_log_skips_comments(tmp_path):
    """Comment lines starting with '#' are not parsed into DnsQuery objects."""
    log_file = tmp_path / "dns.log"
    log_file.write_text(_ZEEK_LOG_CONTENT)
    results = parse_zeek_dns_log(log_file)
    # The content has 2 comment lines; neither should appear as a query.
    for r in results:
        assert not r.queried_name.startswith("#")


def test_parse_zeek_dns_log_skips_null_queries(tmp_path):
    """Rows with '-' in the query column are excluded from results."""
    content = (
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery\n"
        "1700000000.0\tC1\t10.0.0.1\t1\t8.8.8.8\t53\tudp\t1\t0.001\t-\n"
        "1700000001.0\tC2\t10.0.0.1\t2\t8.8.8.8\t53\tudp\t2\t0.001\treal.domain.com\n"
    )
    log_file = tmp_path / "dns.log"
    log_file.write_text(content)
    results = parse_zeek_dns_log(log_file)
    assert len(results) == 1
    assert results[0].queried_name == "real.domain.com"


def test_parse_zeek_dns_log_missing_file():
    """parse_zeek_dns_log returns [] without raising for a non-existent path."""
    result = parse_zeek_dns_log(Path("/nonexistent/path/dns.log"))
    assert result == []


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def test_run_invalid_type_raises():
    """run() raises ValueError for an unrecognised input_type."""
    with pytest.raises(ValueError):
        run(Path("anything"), input_type="invalid")
