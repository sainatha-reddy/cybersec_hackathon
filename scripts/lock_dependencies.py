"""Write exact installed versions for the project's runtime and test dependency graph."""

import importlib.metadata
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]
pending = [line for line in (ROOT / "requirements.txt").read_text().splitlines() if line and not line.startswith("#")]
locked = {}
while pending:
    requirement = Requirement(pending.pop())
    if requirement.marker and not requirement.marker.evaluate({"extra": ""}):
        continue
    key = requirement.name.lower().replace("_", "-")
    if key in locked:
        continue
    distribution = importlib.metadata.distribution(requirement.name)
    locked[key] = distribution.version
    pending.extend(distribution.requires or [])
(ROOT / "requirements.lock").write_text("\n".join(f"{name}=={version}" for name, version in sorted(locked.items())) + "\n", encoding="utf-8")
print(f"Locked {len(locked)} runtime/test dependencies for this platform.")
