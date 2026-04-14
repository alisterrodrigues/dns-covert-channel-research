# Detection benchmark.
# Runs the pcap_analyzer against saved exfiltration session PCAPs and produces
# a comparison report showing how well the detector performs against the basic
# sender versus the evasion variant.

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path

from detection.pcap_analyzer import (
    HIGH_ENTROPY_THRESHOLD,
    LONG_LABEL_THRESHOLD,
    DnsQuery,
    SuspiciousHost,
    analyze,
    parse_pcap,
)
from research.session_generator import generate_benign_session

logger = logging.getLogger(__name__)

_RULE = "━" * 49

# PCAPs under ``sample_data/`` use this suffix for encoded exfil queries.
_BENCHMARK_EXFIL_DOMAIN = "exfil.invalid"


def _remap_benign_timestamps(benign: list[DnsQuery], ts_min: float, ts_max: float) -> list[DnsQuery]:
    """Spread benign synthetic queries across the PCAP time window."""
    raw_ts = [q.timestamp for q in benign]
    r_min, r_max = min(raw_ts), max(raw_ts)
    r_span = max(r_max - r_min, 1e-9)
    span = max(ts_max - ts_min, 1e-9)
    remapped: list[DnsQuery] = []
    for q in benign:
        rel = (q.timestamp - r_min) / r_span
        new_ts = ts_min + rel * span
        remapped.append(DnsQuery(timestamp=new_ts, queried_name=q.queried_name, src_ip=q.src_ip))
    return remapped


def _queries_with_benign_mix(pcap_queries: list[DnsQuery]) -> list[DnsQuery]:
    """Interleave synthetic benign DNS traffic into the same timeline as ``pcap_queries``."""
    if not pcap_queries:
        return pcap_queries
    ts_min = min(q.timestamp for q in pcap_queries)
    ts_max = max(q.timestamp for q in pcap_queries)
    benign = generate_benign_session()
    benign_adj = _remap_benign_timestamps(benign, ts_min, ts_max)
    combined = list(pcap_queries) + benign_adj
    combined.sort(key=lambda q: q.timestamp)
    return combined


@dataclass
class SessionResult:
    """Detection results for a single exfil session PCAP.

    Attributes:
        session_name: Human-readable label, e.g. 'basic' or 'evasion'.
        pcap_path: Path to the PCAP file analyzed.
        queries_detected: Total DNS queries found in the PCAP.
        suspicious_domains: Number of domains flagged as suspicious.
        top_domain: The highest-entropy flagged domain, or None.
        top_confidence: Confidence level of the top domain, or None.
        top_avg_entropy: avg_entropy of the top domain, or None.
        top_avg_label_length: avg_subdomain_length of the top domain, or None.
        top_beacon_confidence: beacon confidence of the top domain, or None.
        detected: True if ``exfil.invalid`` from the mixed capture was flagged.
        signals: List of signal strings from the top domain.
    """

    session_name: str
    pcap_path: str
    queries_detected: int
    suspicious_domains: int
    top_domain: str | None
    top_confidence: str | None
    top_avg_entropy: float | None
    top_avg_label_length: float | None
    top_beacon_confidence: str | None
    detected: bool
    signals: list[str]


def _analyze_pcap(session_name: str, pcap_path: Path, *, mix_benign: bool = True) -> SessionResult:
    """Analyze a single PCAP file and return a SessionResult.

    Args:
        session_name: Label used to identify this session in the report.
        pcap_path: Path to the PCAP file.
        mix_benign: When True, merge synthetic benign queries into the PCAP timeline
            before analysis so the detector sees mixed traffic.

    Returns:
        SessionResult populated from the analyzer output.
    """
    pcap_queries = parse_pcap(pcap_path)
    queries_for_analysis = (
        _queries_with_benign_mix(pcap_queries) if mix_benign and pcap_queries else pcap_queries
    )
    suspicious: list[SuspiciousHost] = analyze(queries_for_analysis)

    exfil_host = next((h for h in suspicious if h.domain == _BENCHMARK_EXFIL_DOMAIN), None)
    top = exfil_host

    return SessionResult(
        session_name=session_name,
        pcap_path=str(pcap_path),
        queries_detected=len(queries_for_analysis),
        suspicious_domains=len(suspicious),
        top_domain=top.domain if top else None,
        top_confidence=top.confidence if top else None,
        top_avg_entropy=top.avg_entropy if top else None,
        top_avg_label_length=top.avg_subdomain_length if top else None,
        top_beacon_confidence=top.beacon_result.confidence if top else None,
        detected=top is not None,
        signals=top.signals if top else [],
    )


def run_benchmark(sample_data_dir: Path) -> dict:
    """Run detection analysis against basic and evasion PCAP sessions.

    Loads ``exfil_session.pcap`` and ``evasion_session.pcap`` from
    ``sample_data_dir``, mixes synthetic benign DNS queries into each capture's
    timeline, and runs ``analyze()`` on the combined query list. Detection is
    reported for ``exfil.invalid`` specifically so benign false positives do not
    count as exfil hits.

    Args:
        sample_data_dir: Path to the directory containing the PCAP files.

    Returns:
        dict with keys:

        - ``sessions``: list of SessionResult dicts (one per PCAP).
        - ``thresholds``: the detection threshold constants used.
        - ``summary``: plain-text conclusion string.
    """
    basic_path = sample_data_dir / "exfil_session.pcap"
    evasion_path = sample_data_dir / "evasion_session.pcap"

    logger.info("running benchmark against %s and %s", basic_path, evasion_path)

    basic_result = _analyze_pcap("basic", basic_path)
    evasion_result = _analyze_pcap("evasion", evasion_path)

    def _confidence_phrase(result: SessionResult) -> str:
        if not result.detected:
            return "not detected"
        return f"detected with {result.top_confidence} confidence"

    summary = (
        f"Basic exfil session: {_confidence_phrase(basic_result)}. "
        f"Evasion variant: {_confidence_phrase(evasion_result)}."
    )

    return {
        "sessions": [asdict(basic_result), asdict(evasion_result)],
        "thresholds": {
            "high_entropy_threshold": HIGH_ENTROPY_THRESHOLD,
            "long_label_threshold": LONG_LABEL_THRESHOLD,
        },
        "summary": summary,
    }


def print_report(results: dict) -> None:
    """Print the benchmark report to stdout in a fixed format.

    Args:
        results: dict as returned by run_benchmark().
    """
    thresholds = results["thresholds"]

    print(_RULE)
    print("  DNS Exfiltration Detection Benchmark")
    print(_RULE)
    print()
    print(
        f"  Thresholds: entropy > {thresholds['high_entropy_threshold']},"
        f" label length > {thresholds['long_label_threshold']}"
    )

    for session in results["sessions"]:
        name = session["session_name"]
        pcap_name = Path(session["pcap_path"]).name
        detected_str = "YES" if session["detected"] else "NO"
        confidence = session["top_confidence"] or "none"
        entropy = f"{session['top_avg_entropy']:.2f}" if session["top_avg_entropy"] is not None else "n/a"
        label_len = f"{session['top_avg_label_length']:.1f}" if session["top_avg_label_length"] is not None else "n/a"
        beacon = session["top_beacon_confidence"] or "n/a"

        print()
        print(f"  [{name} session]")
        print(f"    PCAP:              {pcap_name}")
        print(f"    Queries found:     {session['queries_detected']}")
        print(f"    Domains flagged:   {session['suspicious_domains']}")
        print(f"    Detection:         {detected_str}")
        print(f"    Confidence:        {confidence}")
        print(f"    Avg entropy:       {entropy}")
        print(f"    Avg label length:  {label_len}")
        print(f"    Beacon confidence: {beacon}")
        print("    Signals:")
        if session["signals"]:
            for sig in session["signals"]:
                print(f"      - {sig}")
        else:
            print("      (none)")

    print()
    print(_RULE)
    print("  Summary")
    print(_RULE)
    print(f"  {results['summary']}")
    print(_RULE)


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.WARNING)
    sample_dir = Path(__file__).parent.parent / "sample_data"
    results = run_benchmark(sample_dir)
    print_report(results)
    out_path = Path(__file__).parent / "results" / "benchmark_results.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\n  Results saved to {out_path}")
