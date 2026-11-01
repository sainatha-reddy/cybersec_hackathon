"""Write each incident's evidence packets to its own small .pcap file.

The original packet bytes are copied unchanged (so Wireshark shows exactly
what was captured), but only the packets PacketDoctor cited as evidence.
Note that, unlike the reports, these files do contain payloads, so they are
never anonymised; share them with the same care as the original capture.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

from .._scapy import PcapNgReader, PcapReader, wrpcap
from ..config import DEFAULT_SETTINGS, Settings
from ..ingest import validate_capture
from ..ingest.loader import BoundedCaptureFile, CaptureError


def export_evidence(capture: str | os.PathLike, report: dict, out_dir: str | os.PathLike, settings: Settings = DEFAULT_SETTINGS) -> list[Path]:
    fmt = validate_capture(capture, settings)
    wanted: dict[int, list[str]] = {}
    for inc in report["incidents"]:
        for pid in inc["packet_ids"]:
            wanted.setdefault(pid, []).append(inc["id"])
    if not wanted:
        return []
    buckets: dict[str, list] = {inc["id"]: [] for inc in report["incidents"]}
    last = max(wanted)
    reader_cls = PcapNgReader if fmt == "pcapng" else PcapReader
    idx = 0
    deadline = time.monotonic() + settings.limits.timeout_seconds
    source = BoundedCaptureFile(capture, settings.limits.max_packet_bytes + 65_536, deadline)
    with reader_cls(source) as reader:
        while idx < last:
            if time.monotonic() >= deadline:
                raise CaptureError("Evidence export reached its time limit.")
            try:
                pkt = reader.read_packet()
            except EOFError:
                break
            except Exception:
                break  # damaged tail: export what we have
            if pkt is None:
                break
            idx += 1
            for inc_id in wanted.get(idx, ()):
                buckets[inc_id].append(pkt)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for inc in report["incidents"]:
        pkts = buckets[inc["id"]]
        if not pkts:
            continue
        slug = re.sub(r"[^a-z0-9]+", "_", inc["kind"].lower()).strip("_")
        path = out / f"{inc['id']}_{slug}.pcap"
        wrpcap(str(path), pkts)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        written.append(path)
    return written
