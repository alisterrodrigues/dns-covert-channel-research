# Encoding × jitter detection matrix for synthetic exfil sessions.

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from detection.pcap_analyzer import SuspiciousHost, analyze

from research.session_generator import SessionSpec, generate_session

_MATRIX_PAYLOAD = b"sensitive credential data: api_key=abc123secret " * 20
_JITTER_LEVELS = (0.0, 0.3, 0.8)
_ENCODINGS = ("hex", "base32", "base64")


@dataclass
class MatrixResult:
    """Single cell in the benchmark matrix.

    Attributes:
        encoding: hex, base32, or base64.
        jitter: Jitter fraction used for session generation.
        detected: Whether analyze() flagged the session.
        confidence: Top confidence level or None.
        avg_entropy: Entropy from result or None.
        beacon_confidence: Beacon confidence from result or None.
    """

    encoding: str
    jitter: float
    detected: bool
    confidence: str | None
    avg_entropy: float | None
    beacon_confidence: str | None


def _result_for_domain(
    domain: str, rows: list[SuspiciousHost]
) -> tuple[bool, str | None, float | None, str | None]:
    for host in rows:
        if host.domain == domain:
            return (
                True,
                host.confidence,
                host.avg_entropy,
                host.beacon_result.confidence,
            )
    return (False, None, None, None)


def run_matrix() -> list[MatrixResult]:
    """Run detection across all encoding × jitter combinations.

    Uses a fixed payload and seed (42) for reproducibility.
    """
    results: list[MatrixResult] = []
    domain = "exfil.invalid"

    for encoding in _ENCODINGS:
        for jitter in _JITTER_LEVELS:
            spec = SessionSpec(
                name=f"{encoding}-{jitter}",
                payload=_MATRIX_PAYLOAD,
                encoding=encoding,
                domain=domain,
                jitter=jitter,
                seed=42,
            )
            queries = generate_session(spec)
            flagged = analyze(queries)
            detected, conf, ent, bconf = _result_for_domain(domain, flagged)
            results.append(
                MatrixResult(
                    encoding=encoding,
                    jitter=jitter,
                    detected=detected,
                    confidence=conf,
                    avg_entropy=ent,
                    beacon_confidence=bconf,
                )
            )
    return results


def print_matrix_report(results: list[MatrixResult]) -> None:
    """Print matrix grouped by encoding; jitter levels as columns."""
    by_enc: dict[str, dict[float, MatrixResult]] = {}
    for r in results:
        by_enc.setdefault(r.encoding, {})[r.jitter] = r

    jit_cols = list(_JITTER_LEVELS)
    header = ["Encoding"] + [f"j={j}" for j in jit_cols]
    widths = [len(h) for h in header]
    rows_out: list[list[str]] = []
    for enc in _ENCODINGS:
        row = [enc]
        for j in jit_cols:
            cell = by_enc.get(enc, {}).get(j)
            if cell is None:
                text = "—"
            elif cell.detected:
                c = cell.confidence or "?"
                text = f"Y ({c})"
            else:
                text = "N"
            row.append(text)
        rows_out.append(row)
        for i, t in enumerate(row):
            widths[i] = max(widths[i], len(t))

    def fmt_row(cells: list[str]) -> str:
        return " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells))

    print(fmt_row(header))
    print("-+-".join("-" * w for w in widths))
    for row in rows_out:
        print(fmt_row(row))


if __name__ == "__main__":
    out = run_matrix()
    print_matrix_report(out)
    dest = Path(__file__).parent / "matrix_results.json"
    dest.write_text(json.dumps([asdict(r) for r in out], indent=2))
    print(f"\nWrote {dest}")
