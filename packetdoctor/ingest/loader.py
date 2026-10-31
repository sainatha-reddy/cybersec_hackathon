"""Safe reading of untrusted capture files.

Defences:
* the format is identified by magic bytes, never by file extension;
* file size, packet count, packet size and wall-clock time are capped;
* packets are streamed one at a time (never ``rdpcap``), so memory stays flat;
* a packet that fails to decode is counted and skipped, and a damaged or
  truncated file ends the analysis cleanly with a warning instead of a crash;
* error messages never include stack traces or absolute paths.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from pathlib import Path

from .._scapy import PcapNgReader, PcapReader
from ..config import DEFAULT_SETTINGS, Settings
from ..models import IngestStats, PacketRecord
from .decoder import decode

PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4",  # big-endian, microseconds
    b"\xd4\xc3\xb2\xa1",  # little-endian, microseconds
    b"\xa1\xb2\x3c\x4d",  # big-endian, nanoseconds
    b"\x4d\x3c\xb2\xa1",  # little-endian, nanoseconds
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
MIN_PCAP_BYTES = 24  # global header size


class CaptureError(Exception):
    """A capture file was rejected. The message is safe to show to users."""


def validate_capture(path: str | os.PathLike, settings: Settings = DEFAULT_SETTINGS) -> str:
    """Check that ``path`` is a readable pcap/pcapng within limits.

    Returns ``"pcap"`` or ``"pcapng"``; raises ``CaptureError`` otherwise.
    """
    p = Path(path)
    name = p.name
    if not p.exists():
        raise CaptureError(f"File not found: {name}")
    if not p.is_file():
        raise CaptureError(f"Not a regular file: {name}")
    size = p.stat().st_size
    if size < MIN_PCAP_BYTES:
        raise CaptureError(f"{name} is too small to be a packet capture ({size} bytes).")
    if size > settings.limits.max_file_bytes:
        mb = settings.limits.max_file_bytes // (1024 * 1024)
        raise CaptureError(f"{name} is larger than the {mb} MB limit.")
    try:
        with p.open("rb") as fh:
            magic = fh.read(4)
    except OSError as exc:
        raise CaptureError(f"Cannot read {name}: {exc.strerror or 'I/O error'}") from None
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    raise CaptureError(
        f"{name} is not a pcap or pcapng capture (unrecognised file signature). "
        "Save the capture from Wireshark/tcpdump as .pcap or .pcapng."
    )


def read_capture(
    path: str | os.PathLike,
    stats: IngestStats,
    settings: Settings = DEFAULT_SETTINGS,
) -> Iterator[PacketRecord]:
    """Yield decoded packets one by one, filling ``stats`` along the way."""
    limits = settings.limits
    p = Path(path)
    fmt = validate_capture(p, settings)
    stats.file_name = p.name
    stats.file_format = fmt
    stats.file_bytes = p.stat().st_size

    reader_cls = PcapNgReader if fmt == "pcapng" else PcapReader
    try:
        reader = reader_cls(str(p))
    except Exception:
        raise CaptureError(f"{p.name} has a damaged capture header and cannot be opened.") from None

    started = time.monotonic()
    idx = 0
    with reader:
        while True:
            if idx >= limits.max_packets:
                stats.packet_limit_hit = True
                stats.warnings.append(
                    f"Stopped after {limits.max_packets:,} packets (packet limit). Results cover that part only."
                )
                break
            if idx % 256 == 0 and time.monotonic() - started >= limits.timeout_seconds:
                stats.timed_out = True
                stats.warnings.append(
                    f"Analysis stopped after {limits.timeout_seconds:.0f}s time limit at packet {idx:,}."
                )
                break
            try:
                pkt = reader.read_packet()
            except EOFError:
                break
            except Exception:
                # Corrupt record header / truncated block: stop safely.
                stats.truncated = True
                stats.warnings.append(
                    f"The capture is damaged or truncated after packet {idx:,}; analysed the readable part."
                )
                break
            if pkt is None:
                break
            idx += 1
            stats.packets_read = idx
            try:
                raw_len = len(pkt)
            except Exception:
                raw_len = 0
            if raw_len > limits.max_packet_bytes:
                stats.malformed += 1
                continue
            try:
                rec = decode(idx, pkt)
            except Exception:
                stats.malformed += 1
                continue
            if stats.first_ts is None or rec.ts < stats.first_ts:
                stats.first_ts = rec.ts
            if stats.last_ts is None or rec.ts > stats.last_ts:
                stats.last_ts = rec.ts
            stats.packets_decoded += 1
            yield rec

    if stats.malformed:
        stats.warnings.append(f"{stats.malformed:,} malformed packet(s) were skipped.")
