"""Decide whether an incident is a plain FAULT, an ATTACK, or UNCERTAIN.

Each detector attaches weighted evidence pointing towards 'attack' or towards
'benign fault'. Weights are combined with a noisy-OR (independent clues:
1 - prod(1 - w)), so several weak clues add up but never exceed 1. The
verdict needs a clear margin either way; otherwise the incident is marked
UNCERTAIN instead of guessing. That keeps false alarms low while never
silently dropping a suspicious finding.
"""

from __future__ import annotations

from ..models import Category, Evidence, Verdict

ATTACK_MIN = 0.6
MARGIN = 0.25
SUSPICION_MIN = 0.35


def noisy_or(evidence: list[Evidence]) -> float:
    p = 1.0
    for e in evidence:
        p *= 1.0 - max(0.0, min(1.0, e.weight))
    return 1.0 - p


def decide(category: Category, attack_ev: list[Evidence], benign_ev: list[Evidence]) -> tuple[Verdict, float, float, float]:
    """Return (verdict, confidence, attack score, benign score)."""
    a = noisy_or(attack_ev)
    b = noisy_or(benign_ev)
    if category == Category.ATTACK:
        if a >= ATTACK_MIN and a - b >= MARGIN:
            verdict = Verdict.ATTACK
        elif b >= ATTACK_MIN and b - a >= MARGIN:
            verdict = Verdict.FAULT
        else:
            verdict = Verdict.UNCERTAIN
    else:
        if a >= ATTACK_MIN and a - b >= MARGIN:
            verdict = Verdict.ATTACK
        elif a >= SUSPICION_MIN and a >= b:
            verdict = Verdict.UNCERTAIN
        else:
            verdict = Verdict.FAULT

    if verdict == Verdict.ATTACK:
        confidence = a * (1 - 0.5 * b)
    elif verdict == Verdict.FAULT:
        confidence = max(b, 0.6) * (1 - 0.5 * a)
    else:
        confidence = 0.5 - abs(a - b) / 4
    return verdict, round(max(0.05, min(0.99, confidence)), 2), round(a, 2), round(b, 2)
