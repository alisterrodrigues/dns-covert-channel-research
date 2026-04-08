# Detection benchmark.
# Runs the pcap_analyzer against saved exfiltration session PCAPs and produces
# a comparison report showing how well the detector performs against the basic
# sender versus the evasion variant.

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from detection.pcap_analyzer import (
    HIGH_ENTROPY_THRESHOLD,
    LONG_LABEL_THRESHOLD,
    SuspiciousHost,
    parse_pcap,
    run as analyzer_run,
)

logger = logging.getLogger(__name__)

_RULE = "━" * 49


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
        detected: True if at least one domain was flagged.
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


def _analyze_pcap(session_name: str, pcap_path: Path) -> SessionResult:
    """Analyze a single PCAP file and return a SessionResult.

    Args:
        session_name: Label used to identify this session in the report.
        pcap_path: Path to the PCAP file.

    Returns:
        SessionResult populated from the analyzer output.
    """
    all_queries = parse_pcap(pcap_path)
    suspicious: list[SuspiciousHost] = analyzer_run(pcap_path, input_type="pcap")

    top = suspicious[0] if suspicious else None

    return SessionResult(
        session_name=session_name,
        pcap_path=str(pcap_path),
        queries_detected=len(all_queries),
        suspicious_domains=len(suspicious),
        top_domain=top.domain if top else None,
        top_confidence=top.confidence if top else None,
        top_avg_entropy=top.avg_entropy if top else None,
        top_avg_label_length=top.avg_subdomain_length if top else None,
        top_beacon_confidence=top.beacon_result.confidence if top else None,
        detected=bool(suspicious),
        signals=top.signals if top else [],
    )


def run_benchmark(sample_data_dir: Path) -> dict:
    """Run detection analysis against basic and evasion PCAP sessions.

    Loads ``exfil_session.pcap`` and ``evasion_session.pcap`` from
    ``sample_data_dir`` and runs the pcap_analyzer against each.

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
