# DNS traffic analyzer.
# Parses PCAP files or Zeek dns.log output and flags domains exhibiting
# characteristics consistent with DNS-based data exfiltration.

from __future__ import annotations

import logging
import statistics
from dataclasses import dataclass, field
from pathlib import Path

from detection.beacon_detector import BeaconResult, detect_beaconing
from detection.entropy import subdomain_entropy

logger = logging.getLogger(__name__)

# Flag if average subdomain label length exceeds this value.
LONG_LABEL_THRESHOLD = 20

# Flag if average entropy of subdomain labels exceeds this value.
HIGH_ENTROPY_THRESHOLD = 3.0

# Flag if total query count to a single domain exceeds this in the capture.
HIGH_VOLUME_THRESHOLD = 20


@dataclass
class DnsQuery:
    """A single DNS query extracted from PCAP or Zeek log input.

    Attributes:
        timestamp: Unix timestamp of the query.
        queried_name: The full FQDN queried (e.g. '00_68656c6c6f.exfil.invalid').
        src_ip: Source IP address of the query.
    """

    timestamp: float
    queried_name: str
    src_ip: str


@dataclass
class SuspiciousHost:
    """A domain flagged as suspicious by the pcap analyzer.

    Attributes:
        domain: The base domain (e.g. 'exfil.invalid').
        query_count: Total number of DNS queries to subdomains of this domain.
        avg_subdomain_length: Mean length of queried subdomain labels.
        avg_entropy: Mean Shannon entropy of queried subdomain labels.
        query_interval_std: Standard deviation of inter-query times in seconds.
            0.0 if fewer than 2 queries.
        unique_subdomains: Count of distinct queried subdomains.
        confidence: 'high', 'medium', or 'low'.
        beacon_result: BeaconResult from timing analysis.
        signals: List of human-readable strings describing why this was flagged.
    """

    domain: str
    query_count: int
    avg_subdomain_length: float
    avg_entropy: float
    query_interval_std: float
    unique_subdomains: int
    confidence: str
    beacon_result: BeaconResult
    signals: list[str] = field(default_factory=list)


def extract_subdomain_label(queried_name: str, base_domain: str) -> str:
    """Return the leftmost label of queried_name after stripping the base_domain suffix.

    For example::

        extract_subdomain_label("00_68656c6c6f.exfil.invalid", "exfil.invalid")
        # returns "00_68656c6c6f"

    If queried_name equals base_domain exactly (no subdomain), returns "".
    Trailing dots are stripped from both arguments before comparison.

    Args:
        queried_name: The full FQDN queried.
        base_domain: The base domain to strip.

    Returns:
        The leftmost subdomain label, or "" if none.
    """
    name = queried_name.rstrip(".")
    base = base_domain.rstrip(".")

    if name == base:
        return ""

    suffix = "." + base
    if name.endswith(suffix):
        remainder = name[: -len(suffix)]
        return remainder.split(".")[0]

    return name.split(".")[0]


def parse_pcap(path: Path) -> list[DnsQuery]:
    """Parse a PCAP file and extract DNS A-record queries.

    Uses Scapy's rdpcap to load packets. Filters to UDP port 53 packets
    that carry a DNS layer with at least one question record (qdcount >= 1).
    The queried name is taken from the first question record.

    Args:
        path: Path to a .pcap file.

    Returns:
        List of DnsQuery objects, one per DNS question found.
        Returns an empty list if the file does not exist or cannot be parsed.
    """
    # Scapy is imported here to avoid import-time side effects in test environments.
    from scapy.all import DNS, IP, UDP, rdpcap  # noqa: PLC0415

    try:
        packets = rdpcap(str(path))
    except Exception as exc:
        logger.warning("parse_pcap: failed to read %s: %s", path, exc)
        return []

    queries: list[DnsQuery] = []
    for packet in packets:
        if not (packet.haslayer(UDP) and packet.haslayer(DNS)):
            continue
        if packet[UDP].dport != 53:
            continue
        dns = packet[DNS]
        if dns.qr != 0:
            continue
        if dns.qdcount < 1 or dns.qd is None:
            continue
        try:
            qname = dns.qd.qname.decode().rstrip(".")
            src_ip = packet[IP].src
            timestamp = float(packet.time)
            queries.append(DnsQuery(timestamp=timestamp, queried_name=qname, src_ip=src_ip))
        except Exception as exc:
            logger.debug("parse_pcap: skipping malformed packet: %s", exc)

    return queries


def parse_zeek_dns_log(path: Path) -> list[DnsQuery]:
    """Parse a Zeek dns.log file and extract DNS query records.

    Zeek dns.log is tab-separated. The columns used are:

    - Column 0: ``ts``         — Unix timestamp as a float string
    - Column 2: ``id.orig_h``  — source IP address
    - Column 9: ``query``      — queried FQDN

    Comment lines starting with ``#`` are skipped, as are rows where the
    query field is ``-`` (Zeek's null sentinel).

    Args:
        path: Path to a Zeek dns.log file.

    Returns:
        List of DnsQuery objects. Returns an empty list if the file cannot
        be read.
    """
    queries: list[DnsQuery] = []
    try:
        with path.open() as fh:
            for line in fh:
                if line.startswith("#"):
                    continue
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 10:
                    continue
                queried_name = parts[9].rstrip(".")
                if queried_name == "-":
                    continue
                try:
                    timestamp = float(parts[0])
                    src_ip = parts[2]
                    queries.append(
                        DnsQuery(timestamp=timestamp, queried_name=queried_name, src_ip=src_ip)
                    )
                except Exception as exc:
                    logger.debug("parse_zeek_dns_log: skipping malformed row: %s", exc)
    except Exception as exc:
        logger.warning("parse_zeek_dns_log: failed to read %s: %s", path, exc)

    return queries


def analyze(queries: list[DnsQuery]) -> list[SuspiciousHost]:
    """Analyse a list of DNS queries and return domains flagged as suspicious.

    Queries are grouped by base domain (everything after the first label). For
    each domain with at least 2 queries, aggregate statistics are computed and
    detection thresholds applied.

    Confidence is graded as follows:

    - ``"high"``   — both entropy and label length exceed their thresholds, or
      either entropy or label length exceeds its threshold together with a
      positive beaconing signal.
    - ``"medium"`` — any single signal fires (entropy, label length, query
      volume, or beaconing) without meeting the "high" criteria above.
    - ``"low"``    — no signals fired; domain is not included in results.

    Domains are included in results when confidence is "high" or "medium", or
    when query volume alone exceeds ``HIGH_VOLUME_THRESHOLD``. Results are
    sorted by average entropy descending.

    Args:
        queries: List of DnsQuery objects from parse_pcap or parse_zeek_dns_log.

    Returns:
        List of SuspiciousHost objects for flagged domains.
    """
    if not queries:
        return []

    # Group by base domain (everything after the first label).
    groups: dict[str, list[DnsQuery]] = {}
    for q in queries:
        parts = q.queried_name.split(".")
        if len(parts) < 2:
            continue
        base = ".".join(parts[1:])
        if not base:
            continue
        groups.setdefault(base, []).append(q)

    results: list[SuspiciousHost] = []

    for domain, domain_queries in groups.items():
        if len(domain_queries) < 2:
            continue

        queried_names = [q.queried_name for q in domain_queries]
        timestamps = sorted(q.timestamp for q in domain_queries)

        # Collect subdomain labels, skipping the terminator and empty labels.
        labels = [
            extract_subdomain_label(q.queried_name, domain)
            for q in domain_queries
        ]
        labels = [lbl for lbl in labels if lbl and lbl != "done"]

        if not labels:
            continue

        avg_subdomain_length = statistics.mean(len(lbl) for lbl in labels)
        avg_entropy = statistics.mean(subdomain_entropy(lbl) for lbl in labels)
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
        query_interval_std = statistics.stdev(intervals) if len(intervals) >= 2 else 0.0
        unique_subdomains = len(set(queried_names))
        query_count = len(domain_queries)
        beacon_result = detect_beaconing(timestamps)

        entropy_signal = avg_entropy > HIGH_ENTROPY_THRESHOLD
        length_signal = avg_subdomain_length > LONG_LABEL_THRESHOLD
        volume_signal = query_count > HIGH_VOLUME_THRESHOLD
        beacon_signal = beacon_result.is_beacon
        encoded_signal = entropy_signal and length_signal

        if encoded_signal:
            confidence = "high"
        elif (entropy_signal and beacon_signal) or (length_signal and beacon_signal):
            confidence = "high"
        elif entropy_signal or length_signal or volume_signal or beacon_signal:
            confidence = "medium"
        else:
            confidence = "low"

        if confidence not in ("high", "medium") and not volume_signal:
            continue

        signals: list[str] = []
        if entropy_signal:
            signals.append(
                f"avg entropy {avg_entropy:.2f} > threshold {HIGH_ENTROPY_THRESHOLD}"
            )
        if length_signal:
            signals.append(
                f"avg label length {avg_subdomain_length:.1f} > threshold {LONG_LABEL_THRESHOLD}"
            )
        if volume_signal:
            signals.append(
                f"query volume {query_count} > threshold {HIGH_VOLUME_THRESHOLD}"
            )
        if beacon_result.is_beacon:
            signals.append(
                f"beaconing detected: interval {beacon_result.estimated_interval_seconds:.2f}s,"
                f" confidence {beacon_result.confidence}"
            )

        results.append(
            SuspiciousHost(
                domain=domain,
                query_count=query_count,
                avg_subdomain_length=avg_subdomain_length,
                avg_entropy=avg_entropy,
                query_interval_std=query_interval_std,
                unique_subdomains=unique_subdomains,
                confidence=confidence,
                beacon_result=beacon_result,
                signals=signals,
            )
        )

    results.sort(key=lambda h: h.avg_entropy, reverse=True)
    return results


def run(input_path: Path, input_type: str = "pcap") -> list[SuspiciousHost]:
    """Load a PCAP or Zeek log file and return suspicious domains.

    Args:
        input_path: Path to the input file.
        input_type: Either "pcap" or "zeek". Defaults to "pcap".

    Returns:
        List of SuspiciousHost objects.

    Raises:
        ValueError: If input_type is not "pcap" or "zeek".
    """
    if input_type == "pcap":
        queries = parse_pcap(input_path)
    elif input_type == "zeek":
        queries = parse_zeek_dns_log(input_path)
    else:
        raise ValueError(f"input_type must be 'pcap' or 'zeek', got '{input_type}'")

    return analyze(queries)
