"""Network Health Score: 100 = nothing wrong, 0 = severe problems."""

from __future__ import annotations

from ..models import Verdict

SEVERITY_PENALTY = {1: 2, 2: 6, 3: 12, 4: 20, 5: 30}
VERDICT_FACTOR = {Verdict.ATTACK: 1.3, Verdict.UNCERTAIN: 1.1, Verdict.FAULT: 1.0}


def health_score(incidents: list[dict], capture_duration: float, coverage: str = "complete") -> tuple[int | None, str, str]:
    if coverage == "insufficient_data":
        return None, "Insufficient data", "No usable packets were analysed. Network health cannot be assessed."
    penalty = 0.0
    for inc in incidents:
        base = SEVERITY_PENALTY.get(inc["severity"], 10) * VERDICT_FACTOR[Verdict(inc["verdict"])]
        span = max(0.0, inc["t_end"] - inc["t_start"])
        share = span / capture_duration if capture_duration > 0 else 1.0
        penalty += base * (0.6 + 0.4 * min(1.0, share))  # longer problems hurt more
        penalty += 2 * len(inc["consequences"])
    score = int(round(max(0.0, 100.0 - penalty)))
    attacks = sum(1 for i in incidents if i["verdict"] == Verdict.ATTACK.value)
    uncertain = sum(1 for incident in incidents if incident["verdict"] == Verdict.UNCERTAIN.value)
    if score >= 90:
        grade = "Healthy"
    elif score >= 70:
        grade = "Minor issues"
    elif score >= 40:
        grade = "Degraded"
    else:
        grade = "Critical"
    if not incidents:
        summary = "No faults or attacks were detected in the analysed traffic. This does not prove the network is safe."
    elif attacks:
        summary = f"{attacks} attack{'s' if attacks != 1 else ''} found. Deal with {'these' if attacks != 1 else 'it'} first: attacks can explain other symptoms."
    elif uncertain:
        summary = f"{uncertain} suspicious finding(s) require investigation; malicious intent is not established."
        grade = "Needs review"
    else:
        n = len(incidents)
        summary = f"{n} problem{'s' if n != 1 else ''} found, none of them malicious."
    if coverage == "partial":
        grade = "Partial analysis"
        summary = "Partial analysis: " + summary
    return score, grade, summary
