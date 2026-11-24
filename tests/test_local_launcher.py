"""Local launcher isolation and administrator CLI helper defaults."""

import os
import shutil
import subprocess
from pathlib import Path

from argos.cli import build_parser


def test_helper_defaults_and_explicit_override(monkeypatch):
    monkeypatch.setenv("ARGOS_SLIRP_PATH", "/admin/slirp")
    monkeypatch.setenv("ARGOS_SLIRP_LIBRARY", "/admin/libslirp.so.0")
    parser = build_parser()
    for argv in (
        ["doctor"],
        [
            "recon",
            "run",
            "--mission-id",
            "00000000-0000-0000-0000-000000000001",
            "--public-key",
            "admin.pem",
        ],
    ):
        args = parser.parse_args(argv)
        assert args.slirp == "/admin/slirp"
        assert args.slirp_library == "/admin/libslirp.so.0"
    args = parser.parse_args(["doctor", "--slirp", "/explicit/slirp"])
    assert args.slirp == "/explicit/slirp"


def test_symlink_launcher_preserves_cwd_and_uses_only_project_python(tmp_path):
    project = tmp_path / "project with spaces"
    (project / "scripts").mkdir(parents=True)
    python = project / ".venv/bin/python"
    python.parent.mkdir(parents=True)
    python.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$PWD" "$ARGOS_PROJECT_HOME" '
        '"$ARGOS_TOOL_REGISTRY" "$ARGOS_SLIRP_PATH" "$@"\n'
    )
    python.chmod(0o755)
    script = project / "scripts/argos"
    shutil.copyfile(Path(__file__).parents[1] / "scripts/argos", script)
    script.chmod(0o755)
    installed = tmp_path / "argos"
    installed.symlink_to(script)
    config = tmp_path / "config/argos"
    config.mkdir(parents=True)
    (config / "environment.sh").write_text(
        'export ARGOS_TOOL_REGISTRY="$ARGOS_PROJECT_HOME/../registry.toml"\n'
        'export ARGOS_SLIRP_PATH="/admin/slirp"\n'
    )
    env = dict(os.environ, XDG_CONFIG_HOME=str(config.parent))
    result = subprocess.run(
        [str(installed), "doctor", "--wordlist-home", "a b"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.splitlines() == [
        str(tmp_path),
        str(project),
        str(project / "../registry.toml"),
        "/admin/slirp",
        "-I",
        "-m",
        "argos",
        "doctor",
        "--wordlist-home",
        "a b",
    ]
