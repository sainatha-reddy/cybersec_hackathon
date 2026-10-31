"""Phase 8: the randomised accuracy benchmark (small smoke run)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "benchmark"))

import run as bench  # noqa: E402


def test_benchmark_smoke():
    summary = bench.run(cases=12, seed=777)
    assert summary["false_attack_cases"] == 0
    assert summary["problems"] > 0
    assert summary["correct"] / summary["problems"] >= 0.9
    md = bench.markdown(summary, 777)
    assert "Headline numbers" in md
