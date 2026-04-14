# Sweep entropy and label-length thresholds; report detection vs false positives.

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

import detection.pcap_analyzer as _pa
from detection.pcap_analyzer import DnsQuery, analyze
from research.session_generator import SessionSpec, generate_benign_session, generate_session


@dataclass
class SweepResult:
    """Result for one threshold combination.

    Attributes:
        entropy_threshold: Value tested.
        length_threshold: Value tested.
        true_positives: Malicious sessions correctly flagged.
        false_positives: Benign sessions incorrectly flagged.
        total_malicious: Total malicious sessions tested.
        total_benign: Total benign sessions tested.
        detection_rate: true_positives / total_malicious (0.0 if total_malicious=0).
        false_positive_rate: false_positives / total_benign (0.0 if total_benign=0).
    """

    entropy_threshold: float
    length_threshold: int
    true_positives: int
    false_positives: int
    total_malicious: int
    total_benign: int
    detection_rate: float
    false_positive_rate: float


def _base_domain(queries: list[DnsQuery]) -> str | None:
    if not queries:
        return None
    parts = queries[0].queried_name.split(".")
    if len(parts) < 2:
        return None
    return ".".join(parts[1:])


def _session_flagged(queries: list[DnsQuery], expected_domain: str | None) -> bool:
    if expected_domain is None:
        return False
    return any(h.domain == expected_domain for h in analyze(queries))


def run_sweep(
    entropy_values: list[float],
    length_values: list[int],
    malicious_sessions: list[list[DnsQuery]],
    benign_sessions: list[list[DnsQuery]],
) -> list[SweepResult]:
    """Run detection across all threshold combinations.

    For each (entropy, length) pair, temporarily monkeypatches
    ``HIGH_ENTROPY_THRESHOLD`` and ``LONG_LABEL_THRESHOLD`` in
    ``detection.pcap_analyzer``, runs ``analyze()`` on each session bundle,
    counts true/false positives, then restores the original thresholds.

    Returns:
        ``SweepResult`` rows sorted by ``detection_rate`` descending.
    """
    orig_entropy = _pa.HIGH_ENTROPY_THRESHOLD
    orig_length = _pa.LONG_LABEL_THRESHOLD
    malicious_domains = [_base_domain(s) for s in malicious_sessions]
    benign_domains = [_base_domain(s) for s in benign_sessions]
    results: list[SweepResult] = []

    try:
        for ent in entropy_values:
            for ln in length_values:
                _pa.HIGH_ENTROPY_THRESHOLD = ent
                _pa.LONG_LABEL_THRESHOLD = ln

                tp = 0
                for qs, dom in zip(malicious_sessions, malicious_domains, strict=True):
                    if _session_flagged(qs, dom):
                        tp += 1

                fp = 0
                for qs, dom in zip(benign_sessions, benign_domains, strict=True):
                    if _session_flagged(qs, dom):
                        fp += 1

                tm = len(malicious_sessions)
                tb = len(benign_sessions)
                det = tp / tm if tm else 0.0
                fpr = fp / tb if tb else 0.0
                results.append(
                    SweepResult(
                        entropy_threshold=ent,
                        length_threshold=ln,
                        true_positives=tp,
                        false_positives=fp,
                        total_malicious=tm,
                        total_benign=tb,
                        detection_rate=det,
                        false_positive_rate=fpr,
                    )
                )
    finally:
        _pa.HIGH_ENTROPY_THRESHOLD = orig_entropy
        _pa.LONG_LABEL_THRESHOLD = orig_length

    results.sort(key=lambda r: r.detection_rate, reverse=True)
    return results


def print_sweep_table(results: list[SweepResult]) -> None:
    """Print a formatted ASCII table of sweep results."""
    headers = ("Entropy Thresh", "Length Thresh", "Detection Rate", "FP Rate")
    rows = [
        (
            f"{r.entropy_threshold:.2f}",
            str(r.length_threshold),
            f"{r.detection_rate:.2%}",
            f"{r.false_positive_rate:.2%}",
        )
        for r in results
    ]
    widths = [max(len(h), max((len(row[i]) for row in rows), default=0)) for i, h in enumerate(headers)]
    sep = "-+-".join("-" * w for w in widths)
    head = " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(head)
    print(sep)
    for row in rows:
        print(" | ".join(row[i].ljust(widths[i]) for i in range(len(row))))


def default_sweep_sessions() -> tuple[list[list[DnsQuery]], list[list[DnsQuery]]]:
    """Build a small default malicious/benign session set for CLI sweep."""
    payload = b"benchmark sweep payload " * 8
    malicious: list[list[DnsQuery]] = []
    for name, enc, seed in (
        ("hex-a", "hex", 42),
        ("hex-b", "hex", 43),
        ("b32", "base32", 44),
        ("b64", "base64", 45),
    ):
        malicious.append(
            generate_session(
                SessionSpec(
                    name=name,
                    payload=payload,
                    encoding=enc,
                    seed=seed,
                    inter_query_delay=0.5,
                    jitter=0.1,
                )
            )
        )
    benign = [
        generate_benign_session(seed=99),
        generate_benign_session(seed=100, count=25),
    ]
    return malicious, benign


def default_entropy_grid() -> list[float]:
    return [2.0, 2.5, 3.0, 3.5, 4.0, 4.5]


def default_length_grid() -> list[int]:
    return [12, 16, 20, 24, 28, 32]


if __name__ == "__main__":
    m, b = default_sweep_sessions()
    grid = run_sweep(default_entropy_grid(), default_length_grid(), m, b)
    print_sweep_table(grid)
    out_path = Path(__file__).parent / "sweep_results.json"
    out_path.write_text(json.dumps([asdict(r) for r in grid], indent=2))
    print(f"\nWrote {out_path}")
