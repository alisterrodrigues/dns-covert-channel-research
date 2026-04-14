# Exfiltration configuration.
# All values read from here — nothing hardcoded in sender or encoder.

from dataclasses import dataclass


@dataclass
class ExfilConfig:
    # Domain queries are sent to: chunk.target_domain
    target_domain: str = "exfil.invalid"

    # DNS server to send queries to. 127.0.0.1 causes queries to fail silently
    # but still generates full PCAP traffic — correct default for lab capture.
    dns_server: str = "127.0.0.1"

    # Max characters per subdomain chunk. Must be <= 60 to leave room for
    # the 2-digit sequence prefix (e.g., "00_") and stay under DNS 63-char label limit.
    chunk_size: int = 30

    # Seconds between successive DNS queries. Simulates attacker pacing.
    inter_query_delay_seconds: float = 0.5

    # UDP source port for crafted DNS packets.
    src_port: int = 12345

    # Encoding scheme applied to payload bytes before chunking.
    # Supported values: "hex", "base32", "base64".
    encoding: str = "hex"
