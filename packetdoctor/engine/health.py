"""Network Health Score: 100 = nothing wrong, 0 = severe problems."""

from __future__ import annotations

from ..models import Verdict

SEVERITY_PENALTY = {1: 2, 2: 6, 3: 12, 4: 20, 5: 30}
VERDICT_FACTOR = {Verdict.ATTACK: 1.3, Verdict.UNCERTAIN: 1.1, Verdict.FAULT: 1.0}


def health_score(incidents: list[dict], capture_duration: float) -> tuple[int, str, str]:
    penalty = 0.0
    for inc in incidents:
        base = SEVERITY_PENALTY.get(inc["severity"], 10) * VERDICT_FACTOR[Verdict(inc["verdict"])]
        span = max(0.0, inc["t_end"] - inc["t_start"])
        share = span / capture_duration if capture_duration > 0 else 1.0
        penalty += base * (0.6 + 0.4 * min(1.0, share))  # longer problems hurt more
        penalty += 2 * len(inc["consequences"])
    score = int(round(max(0.0, 100.0 - penalty)))
    attacks = sum(1 for i in incidents if i["verdict"] == Verdict.ATTACK.value)
    if score >= 90:
        grade = "Healthy"
    elif score >= 70:
        grade = "Minor issues"
    elif score >= 40:
        grade = "Degraded"
    else:
        grade = "Critical"
    if not incidents:
        summary = "No faults or attacks were found in this capture. The network looks healthy."
    elif attacks:
        summary = f"{attacks} attack(s) found. Deal with these first: they can explain other symptoms."
    else:
        summary = f"{len(incidents)} problem(s) found, none of them malicious."
    return score, grade, summary
