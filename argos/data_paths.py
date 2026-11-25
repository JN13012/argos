"""Resolve persistent data locations for the CLI and the local Ollama launcher."""

import os
import stat
from pathlib import Path

_CHECKOUT = Path(__file__).resolve().parents[1]
_IN_CHECKOUT = (_CHECKOUT / "pyproject.toml").is_file()
_DEFAULT_HOME = (
    _CHECKOUT / "data" if _IN_CHECKOUT else Path.home() / ".local/share/argos/data"
)

DATA_AREAS = (
    "ollama",
    "memory",
    "knowledge",
    "missions",
    "skills",
    "learning",
    "profiles",
    "qualification",
    "backups",
)


def data_home() -> Path:
    configured = os.environ.get("ARGOS_DATA_HOME")
    if not configured:
        return _DEFAULT_HOME
    # Relative configuration stays portable across working directories.
    return Path(os.path.abspath(_DEFAULT_HOME.parent / Path(configured).expanduser()))


def data_path(area: str, *parts: str) -> Path:
    return data_home().joinpath(area, *parts)


def _private_directory(path: Path, *, scaffold: bool = False) -> None:
    if path.resolve() != path:
        raise PermissionError(f"Symlinked data directory: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise PermissionError(f"Data directory must belong to the current user: {path}")
    if info.st_mode & 0o077:
        if not scaffold or info.st_mode & 0o022:
            raise PermissionError(f"Data directory must be private (0700): {path}")
        path.chmod(stat.S_IMODE(info.st_mode) & 0o700)


def prepare_area(area: str) -> Path:
    root = data_home()
    scaffold = _IN_CHECKOUT and root == _DEFAULT_HOME
    _private_directory(root, scaffold=scaffold)
    path = root / area
    _private_directory(path, scaffold=scaffold)
    return path


def initialize_data() -> Path:
    for area in DATA_AREAS:
        prepare_area(area)
    return data_home()


def ollama_home() -> Path:
    explicit = os.environ.get("ARGOS_LLM_HOME")
    return Path(explicit) if explicit else prepare_area("ollama")


if __name__ == "__main__":
    # Invoked as an isolated stdlib-only script by scripts/llm/ollama-local.
    try:
        print(ollama_home())
    except (OSError, ValueError, RuntimeError) as error:
        raise SystemExit(f"ollama-local: {error}") from error
