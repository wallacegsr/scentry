"""Installs the scanners in the image (docker/Dockerfile, `tools` stage).

Each docker/tools/<name>/ is a project that only pins one scanner; its uv.lock pins every
package the scanner needs, each file with its hash. This installs each into its own
environment, /opt/tools/<name>, from that lock: uv refuses a file whose hash differs and
a lock that no longer matches the pin. Then the scanner's own commands are linked into
/opt/tools/bin, as `uv tool install` would.

Wheels only: no package's setup code runs, except Barkley's, which isn't on PyPI and is
built from its repository at the locked commit, with the locked hatchling.

    python3 install.py SOURCE_DIR TARGET_DIR
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

# Which of a distribution's files went into the environment's bin directory.
COMMANDS = """
import importlib.metadata as m, os, sys
bin_dir = os.path.join(sys.prefix, "bin")
for f in m.distribution(sys.argv[1]).files or []:
    path = os.path.normpath(f.locate())
    if os.path.dirname(path) == bin_dir:
        print(os.path.basename(path))
"""


def uv_sync(project: Path, env: dict[str, str], *extra: str) -> None:
    cmd = ["uv", "sync", "--locked", "--no-dev", "--project", str(project), *extra]
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, env=env, check=True)


def install(project: Path, target: Path) -> list[str]:
    config = tomllib.loads((project / "pyproject.toml").read_text())
    scanner = re.split(r"[\s\[=<>!~@;]", config["project"]["dependencies"][0], maxsplit=1)[0]
    built = config.get("tool", {}).get("uv", {}).get("no-build-isolation-package", [])
    venv = target / project.name
    env = {**os.environ, "UV_PROJECT_ENVIRONMENT": str(venv)}

    # Everything from wheels first; then the one package that is built, if any, which
    # builds inside that environment with the build backend just installed from the lock.
    skip = [arg for name in built for arg in ("--no-install-package", name)]
    uv_sync(project, env, "--no-build", *skip)
    if built:
        uv_sync(project, env)

    names = subprocess.run([str(venv / "bin" / "python"), "-I", "-c", COMMANDS, scanner],
                           check=True, capture_output=True, text=True).stdout.split()  # fmt: skip
    if not names:
        sys.exit(f"{scanner} installed no commands")
    (target / "bin").mkdir(exist_ok=True)
    for name in names:
        (target / "bin" / name).symlink_to(venv / "bin" / name)
    return names


def main() -> None:
    source, target = Path(sys.argv[1]), Path(sys.argv[2])
    for project in sorted(p.parent for p in source.glob("*/pyproject.toml")):
        print(f"{project.name}: {', '.join(install(project, target))}", flush=True)


if __name__ == "__main__":
    main()
