# Synthetic DNS session generator.
# Produces reproducible DnsQuery lists for benchmarking without sending
# any real packets. Timestamps are generated from a fixed epoch with
# optional Gaussian jitter to simulate varying inter-query timing.

from __future__ import annotations

import random
from dataclasses import dataclass

from detection.pcap_analyzer import DnsQuery
from exfil.encoder import DNSExfilEncoder

# Fixed base epoch used for all synthetic sessions — keeps results reproducible
# across runs regardless of wall-clock time.
_BASE_TIMESTAMP = 1_700_000_000.0

# Subdomain labels used for benign-looking traffic generation.
_BENIGN_LABELS = ["www", "mail", "api", "cdn", "static", "assets", "auth", "login"]


@dataclass
class SessionSpec:
    """Specification for a synthetic exfiltration query session.

    Attributes:
        name: Human-readable label for the session.
        payload: Bytes to encode and transmit.
        encoding: Encoding scheme: 'hex', 'base32', or 'base64'.
        domain: Base domain for DNS queries.
        chunk_size: Characters per encoded subdomain label.
        inter_query_delay: Mean seconds between successive queries.
        jitter: Fractional standard deviation applied to each delay.
            0.0 produces perfectly regular spacing; higher values introduce
            Gaussian noise proportional to inter_query_delay.
        src_ip: Source IP address written into each DnsQuery object.
        seed: RNG seed for reproducible timestamp generation.
    """

    name: str
    payload: bytes
    encoding: str = "hex"
    domain: str = "exfil.invalid"
    chunk_size: int = 30
    inter_query_delay: float = 0.5
    jitter: float = 0.0
    src_ip: str = "10.0.0.1"
    seed: int = 42


def generate_session(spec: SessionSpec) -> list[DnsQuery]:
    """Generate a reproducible list of DnsQuery objects from a SessionSpec.

    Encodes the payload using DNSExfilEncoder, then assigns each FQDN a
    timestamp derived from the fixed base epoch plus accumulated delays with
    optional Gaussian jitter. The terminator query is included.

    Args:
        spec: Session configuration.

    Returns:
        Ordered list of DnsQuery objects, one per FQDN including the terminator.
    """
    rng = random.Random(spec.seed)
    encoder = DNSExfilEncoder(
        target_domain=spec.domain,
        chunk_size=spec.chunk_size,
        encoding=spec.encoding,
    )
    encode_result = encoder.encode(spec.payload)

    queries: list[DnsQuery] = []
    timestamp = _BASE_TIMESTAMP
    for fqdn in encode_result.fqdns:
        queries.append(DnsQuery(timestamp=timestamp, queried_name=fqdn, src_ip=spec.src_ip))
        jitter_delta = rng.gauss(0.0, spec.inter_query_delay * spec.jitter) if spec.jitter > 0 else 0.0
        timestamp += max(0.0, spec.inter_query_delay + jitter_delta)

    return queries


def generate_benign_session(
    domain: str = "google.com",
    count: int = 20,
    src_ip: str = "10.0.0.2",
    seed: int = 99,
) -> list[DnsQuery]:
    """Generate a list of benign-looking DnsQuery objects with human-like timing.

    Uses short, common subdomain labels and irregular inter-query delays to
    simulate organic browser or application traffic rather than automated
    exfiltration.

    Args:
        domain: Base domain for the generated queries.
        count: Number of queries to generate.
        src_ip: Source IP address for each DnsQuery.
        seed: RNG seed for reproducibility.

    Returns:
        List of DnsQuery objects with realistic-looking labels and timing.
    """
    rng = random.Random(seed)
    queries: list[DnsQuery] = []
    timestamp = _BASE_TIMESTAMP
    for _ in range(count):
        label = rng.choice(_BENIGN_LABELS)
        fqdn = f"{label}.{domain}"
        queries.append(DnsQuery(timestamp=timestamp, queried_name=fqdn, src_ip=src_ip))
        # High-variance delay simulates human-driven request timing.
        timestamp += rng.uniform(0.5, 15.0)

    return queries
