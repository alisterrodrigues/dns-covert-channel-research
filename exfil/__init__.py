from __future__ import annotations

from exfil.config import ExfilConfig
from exfil.encoder import DNSExfilEncoder, EncodeResult

__all__ = [
    "ExfilConfig",
    "DNSExfilEncoder",
    "EncodeResult",
    "DNSSender",
    "ExfilResult",
]


def __getattr__(name: str):
    """Lazy-import sender types so ``import exfil.encoder`` does not require Scapy."""
    if name == "DNSSender":
        from exfil.dns_sender import DNSSender

        return DNSSender
    if name == "ExfilResult":
        from exfil.dns_sender import ExfilResult

        return ExfilResult
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
