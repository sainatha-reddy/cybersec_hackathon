"""Retrieve named public Wireshark examples and verify pinned content hashes."""

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from packetdoctor.engine import analyze

MANIFEST = ROOT / "benchmark/public-captures.json"


def run(directory, fetch=False, record=False):
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    directory.mkdir(parents=True, exist_ok=True)
    results = []
    for capture in manifest:
        path = directory / capture["name"]
        if not path.exists():
            if not fetch:
                raise SystemExit(f"Missing {path.name}. Run with --fetch to retrieve the public sample.")
            request = urllib.request.Request(capture["url"], headers={"User-Agent": "PacketDoctor evaluation"})
            with urllib.request.urlopen(request, timeout=30) as response:
                data = response.read(10 * 1024 * 1024 + 1)
            if len(data) > 10 * 1024 * 1024:
                raise SystemExit("Public sample exceeds the 10 MB download limit.")
            path.write_bytes(data)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if record:
            capture["sha256"] = digest
        elif not capture.get("sha256") or digest != capture["sha256"]:
            raise SystemExit(f"Hash mismatch for {path.name}; source content changed.")
        report = analyze(path)
        findings = [{"kind": incident["kind"], "verdict": incident["verdict"]} for incident in report["incidents"]]
        observed = {(finding["kind"], finding["verdict"]) for finding in findings}
        required = {(finding["kind"], finding["verdict"]) for finding in capture["required"]}
        passed = required <= observed and (capture["allow_attack"] or not report["summary"]["attacks"]) and not report["detector_errors"]
        results.append({"name": path.name, "sha256": digest, "passed": passed, "coverage": report["analysis"]["coverage"], "findings": findings})
    if record:
        MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (ROOT / "docs/public-capture-results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(results, indent=2))
    return all(result["passed"] for result in results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "tmp/public-captures")
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--record-hashes", action="store_true")
    arguments = parser.parse_args()
    raise SystemExit(0 if run(arguments.directory, arguments.fetch, arguments.record_hashes) else 1)
