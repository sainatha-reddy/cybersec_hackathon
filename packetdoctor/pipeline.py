"""Single streaming pass: read -> update state -> run every detector."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .config import DEFAULT_SETTINGS, Settings
from .detectors import ALL_DETECTORS
from .ingest import read_capture
from .models import IngestStats, Symptom
from .state import NetworkState


@dataclass
class DetectionResult:
    stats: IngestStats
    state: NetworkState
    symptoms: list[Symptom] = field(default_factory=list)
    detector_errors: list[str] = field(default_factory=list)


def detect(path: str | os.PathLike, settings: Settings = DEFAULT_SETTINGS, detectors=None) -> DetectionResult:
    stats = IngestStats()
    state = NetworkState(settings)
    active = [cls(settings) for cls in (detectors or ALL_DETECTORS)]
    errors: list[str] = []
    for rec in read_capture(path, stats, settings):
        ctx = state.update(rec)
        for det in active:
            try:
                det.on_packet(rec, ctx, state)
            except Exception as exc:  # one broken detector must not stop the analysis
                if len(errors) < 20:
                    errors.append(f"{det.name}: {type(exc).__name__} at packet {rec.idx}")
    symptoms: list[Symptom] = []
    for det in active:
        try:
            symptoms.extend(det.finalize(state))
        except Exception as exc:
            errors.append(f"{det.name}: {type(exc).__name__} while finishing")
    symptoms.sort(key=lambda s: (s.t_start, -s.severity))
    return DetectionResult(stats=stats, state=state, symptoms=symptoms, detector_errors=errors)
