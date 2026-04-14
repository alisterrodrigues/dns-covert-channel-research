# Exfiltration configuration shared by the sender and encoder.

from dataclasses import dataclass


@dataclass
class ExfilConfig:
    # Domain queries are sent to: chunk.target_domain
    target_domain: str = "exfil.invalid"

    # DNS server IP to send queries to.
    dns_server: str = "127.0.0.1"

    # UDP destination port for DNS queries. Set to 5353 when targeting the
    # built-in receiver (python -m cli.main receive). Use 53 for real DNS
    # infrastructure or loopback captures via tcpdump.
    dns_server_port: int = 53

    # Max characters of encoded payload per label. Capped by the encoder so
    # the full wire label (sequence + encoding tag + chunk) fits in 63 octets.
    chunk_size: int = 30

    # Seconds between successive DNS queries in the basic sender.
    inter_query_delay_seconds: float = 0.5

    # UDP source port for crafted DNS packets.
    src_port: int = 12345

    # Encoding scheme applied to payload bytes before chunking.
    # Supported values: "hex", "base32", "base64".
    encoding: str = "hex"
