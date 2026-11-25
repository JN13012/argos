import os
import subprocess
from pathlib import Path

from argos.cli import main
from argos.data_paths import DATA_AREAS, data_home

CHECKOUT = Path(__file__).resolve().parents[1]


def test_relative_data_home_is_anchored_to_checkout(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ARGOS_DATA_HOME", raising=False)
    assert data_home() == CHECKOUT / "data"
    monkeypatch.setenv("ARGOS_DATA_HOME", "custom storage")
    assert data_home() == CHECKOUT / "custom storage"


def test_initialize_and_use_mission_store_from_other_directory(tmp_path, monkeypatch):
    home = tmp_path / "private data"
    monkeypatch.setenv("ARGOS_DATA_HOME", str(home))
    monkeypatch.chdir(tmp_path)
    assert main(["data", "init"]) == 0
    assert main(["data", "init"]) == 0
    for path in [home, *(home / area for area in DATA_AREAS)]:
        assert path.stat().st_mode & 0o777 == 0o700

    assert main(["web", "init", "app.example.com", "--json"]) == 0
    assert (home / "missions/missions.sqlite3").stat().st_mode & 0o777 == 0o600

    explicit = tmp_path / "archive/explicit.sqlite3"
    args = ["web", "init", "app.example.com", "--db", "archive/explicit.sqlite3"]
    assert main(args) == 0
    assert explicit.is_file()


def test_data_init_refuses_symlinked_area(tmp_path, monkeypatch):
    home = tmp_path / "private"
    home.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir()
    (home / "ollama").symlink_to(outside)
    monkeypatch.setenv("ARGOS_DATA_HOME", str(home))
    assert main(["data", "init"]) == 1
    assert outside.stat().st_mode & 0o077


def test_ollama_launcher_honors_data_home_and_local_overrides(tmp_path):
    home = tmp_path / "private data"
    runtime = home / "ollama/runtime/bin/ollama"
    runtime.parent.mkdir(parents=True, mode=0o700)
    home.chmod(0o700)
    (home / "ollama").chmod(0o700)
    runtime.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$OLLAMA_MODELS" "$OLLAMA_HOST" "$@"\n'
    )
    runtime.chmod(0o700)
    launcher = CHECKOUT / "scripts/llm/ollama-local"
    env = dict(os.environ, ARGOS_DATA_HOME=str(home), ARGOS_OLLAMA_PORT="11534")
    env.pop("ARGOS_LLM_HOME", None)
    env.pop("OLLAMA_MODELS", None)
    result = subprocess.check_output([launcher, "list"], cwd=tmp_path, env=env)
    assert result.decode().splitlines() == [
        str(home / "ollama/models"),
        "127.0.0.1:11534",
        "list",
    ]
    env.update(ARGOS_LLM_HOME="private data/ollama", OLLAMA_MODELS="custom models")
    result = subprocess.check_output([launcher, "list"], cwd=tmp_path, env=env)
    assert result.decode().splitlines() == ["custom models", "127.0.0.1:11534", "list"]
