from __future__ import annotations

from collections.abc import Iterable

from ..config import Settings
from ..models import PacketRecord, Symptom
from ..state import NetworkState, PacketContext


class Detector:
    """A detector watches every packet and reports Symptoms at the end.

    Detectors only read ``PacketRecord`` and the shared ``NetworkState``; all
    the decision logic is in the detector itself."""

    name = "base"

    def __init__(self, settings: Settings):
        self.settings = settings
        self.t = settings.thresholds
        self.max_ids = settings.limits.max_evidence_per_symptom

    def on_packet(self, rec: PacketRecord, ctx: PacketContext, state: NetworkState) -> None:
        pass

    def finalize(self, state: NetworkState) -> list[Symptom]:
        return []

    def ids(self, *groups: Iterable[int]) -> list[int]:
        """Merge packet-id lists into a sorted, de-duplicated, capped list."""
        merged = sorted({i for g in groups for i in g})
        if len(merged) <= self.max_ids:
            return merged
        # keep the start and the end of the evidence, which is what people look at
        half = self.max_ids // 2
        return merged[:half] + merged[-half:]


def severity_from_ratio(ratio: float, steps=((0.15, 4), (0.07, 3))) -> int:
    for limit, sev in steps:
        if ratio >= limit:
            return sev
    return 2


def track_span(span: list, ts: float) -> None:
    """Keep ``span`` as [first, last] timestamp."""
    if not span:
        span.extend((ts, ts))
    else:
        span[0] = min(span[0], ts)
        span[1] = max(span[1], ts)
