import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SAMPLES = ROOT / "samples"


@pytest.fixture(scope="session")
def samples_dir() -> Path:
    if not (SAMPLES / "clean.pcap").exists():
        from samples.generate import generate

        generate(SAMPLES)
    return SAMPLES
