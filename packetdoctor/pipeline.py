"""Single streaming pass: read -> update state -> run every detector."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from .config import DEFAULT_SETTINGS, Settings
from .detectors import ALL_DETECTORS
from .ingest import read_capture
from .models import IngestStats, Symptom
from .state import NetworkState
from .state.budget import StateBudget, StateLimitReached


@dataclass
class DetectionResult:
    stats: IngestStats
    state: NetworkState
    symptoms: list[Symptom] = field(default_factory=list)
    detector_errors: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)


def detect(path: str | os.PathLike, settings: Settings = DEFAULT_SETTINGS, detectors=None) -> DetectionResult:
    stats = IngestStats()
    state = NetworkState(settings)
    active = [cls(settings) for cls in (detectors or ALL_DETECTORS)]
    budget = StateBudget(settings.limits.max_state_items, settings.limits.max_hosts)
    for owner in (state, state.hosts, state.dns, state.relay, state.flows, *active):
        budget.bind(owner)
    started = time.monotonic()
    evidence = {}
    errors: list[str] = []
    for rec in read_capture(path, stats, settings):
        try:
            ctx = state.update(rec)
        except StateLimitReached as exc:
            stats.warnings.append(str(exc))
            break
        except Exception as exc:
            errors.append(f"Network state: {type(exc).__name__} at packet {rec.idx}")
            break
        exhausted = False
        for det in active:
            try:
                det.on_packet(rec, ctx, state)
            except StateLimitReached as exc:
                stats.warnings.append(str(exc))
                exhausted = True
                break
            except Exception as exc:  # one broken detector must not stop the analysis
                if len(errors) < 20:
                    errors.append(f"{det.name}: {type(exc).__name__} at packet {rec.idx}")
        if len(evidence) < min(settings.limits.max_packets, 20_000):
            evidence[rec.idx] = rec
        if exhausted:
            break
        if time.monotonic() - started >= settings.limits.timeout_seconds:
            stats.timed_out = True
            stats.warnings.append("Analysis reached its processing deadline; results are partial.")
            break
    symptoms: list[Symptom] = []
    for det in active:
        try:
            for symptom in det.finalize(state):
                if len(symptoms) >= settings.limits.max_incidents:
                    stats.warnings.append("Incident limit reached; additional findings were omitted.")
                    break
                symptoms.append(symptom)
        except Exception as exc:
            errors.append(f"{det.name}: {type(exc).__name__} while finishing")
    symptoms.sort(key=lambda s: (s.t_start, -s.severity))
    evicted = state.flows.flows.evicted + state.flows.retired_dropped + state.dns.queries.evicted + state.hosts.ip_macs.evicted
    if evicted:
        stats.warnings.append(f"State tables evicted {evicted:,} entries; some earlier activity may be missing from diagnoses.")
    return DetectionResult(stats=stats, state=state, symptoms=symptoms, detector_errors=errors, evidence=evidence)
