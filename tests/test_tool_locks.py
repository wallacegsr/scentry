"""The scanners' Python dependencies (docker/tools/<name>/) are locked, each file hashed."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "docker" / "tools"
PROJECTS = sorted(p.parent for p in TOOLS.glob("*/pyproject.toml"))
ARCHES = {"x86_64", "aarch64"}


def test_every_python_scanner_has_a_project():
    assert {p.name for p in PROJECTS} == {"bandit", "barkley", "guarddog", "semgrep", "zizmor"}
    dockerfile = (TOOLS.parent / "Dockerfile").read_text()
    assert "install.py" in dockerfile and "uv tool install" not in dockerfile


@pytest.mark.parametrize("project", PROJECTS, ids=lambda p: p.name)
def test_pinned_and_locked(project):
    config = tomllib.loads((project / "pyproject.toml").read_text())
    pin = config["project"]["dependencies"][0]
    # The scanner itself: an exact version, or a repository at an exact commit.
    assert re.search(r"==[\w.]+$", pin) or re.search(r"@ git\+https://\S+@[0-9a-f]{40}$", pin)
    uv = config["tool"]["uv"]
    assert uv["package"] is False
    assert {m for e in uv["required-environments"] for m in ARCHES if m in e} == ARCHES

    lock = tomllib.loads((project / "uv.lock").read_text())
    packages = [p for p in lock["package"] if "virtual" not in p["source"]]
    assert packages
    for p in packages:
        if "git" in p["source"]:
            assert re.search(r"#[0-9a-f]{40}$", p["source"]["git"]), p["name"]
            continue
        # A wheel for each image, and every file it might fetch hashed.
        assert p.get("wheels"), f"{p['name']} has no wheel: it would be built"
        files = p["wheels"] + ([p["sdist"]] if "sdist" in p else [])
        assert all(f.get("hash", "").startswith("sha256:") for f in files), p["name"]
