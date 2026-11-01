"""Publish the PacketDoctor dashboard as a Hugging Face Docker Space.

Usage:
    pip install huggingface_hub            # once, in any environment
    set HF_TOKEN=hf_...                     # a token with "write" access
    python scripts/deploy_hf.py [--space your-name/packetdoctor]

The Space gets only what the container needs (Dockerfile, the package and the
sample captures) plus a Space README with the Hugging Face settings block.
Re-running the script pushes a new version to the same Space.
"""

from __future__ import annotations

import argparse
import os
import shutil
import tempfile
from pathlib import Path

from huggingface_hub import HfApi

ROOT = Path(__file__).resolve().parent.parent
GITHUB = "https://github.com/sainatha-reddy/cybersec_hackathon"

SPACE_README = """---
title: PacketDoctor
emoji: 🩺
colorFrom: green
colorTo: gray
sdk: docker
app_port: 7860
pinned: false
license: mit
short_description: Finds faults and attacks in packet captures
---

# PacketDoctor

Upload a `.pcap` or `.pcapng` capture, or pick one of the bundled samples.
PacketDoctor separates ordinary network faults from deliberate attacks,
explains each one in plain language, and lists the exact packets as evidence.

This is a hosted demo. Uploaded captures are analysed on this server and
deleted straight after, and uploads are limited to 50 MB. For sensitive
captures, install PacketDoctor and run it on your own computer.

Source code and documentation: {github}
"""


def stage(target: Path) -> None:
    for name in ("Dockerfile", ".dockerignore", "requirements.lock", "LICENSE"):
        shutil.copy2(ROOT / name, target / name)
    shutil.copytree(ROOT / "packetdoctor", target / "packetdoctor", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (target / "samples").mkdir()
    for capture in sorted((ROOT / "samples").glob("*.pcap*")):
        shutil.copy2(capture, target / "samples" / capture.name)
    (target / "README.md").write_text(SPACE_README.format(github=GITHUB), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--space", help="Space id as owner/name (default: <your user>/packetdoctor)")
    args = parser.parse_args()

    api = HfApi(token=os.environ.get("HF_TOKEN"))
    space = args.space or f"{api.whoami()['name']}/packetdoctor"
    api.create_repo(space, repo_type="space", space_sdk="docker", exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="packetdoctor-space-") as tmp:
        stage(Path(tmp))
        api.upload_folder(
            folder_path=tmp, repo_id=space, repo_type="space",
            commit_message="Deploy PacketDoctor dashboard", delete_patterns=["*"],
        )

    owner, name = space.split("/")
    print(f"Space page: https://huggingface.co/spaces/{space}")
    print(f"Direct app: https://{owner}-{name}.hf.space".lower().replace("_", "-"))
    print("The first build takes a few minutes; watch its progress on the Space page.")


if __name__ == "__main__":
    main()
