"""File IO helper utilities with explicit path handling."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable


DEFAULT_ENCODING = "utf-8"


def ensure_path(path_str: str) -> Path:
    """Return a ``Path`` ensuring the file exists."""
    path = Path(path_str).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Path not found: {path}")
    return path


def load_text(path_str: str) -> str:
    """Load file contents using the default encoding."""
    path = ensure_path(path_str)
    return path.read_text(encoding=DEFAULT_ENCODING)


def save_text(path_str: str, content: str) -> Path:
    """Persist text to disk with parent directory creation."""
    path = Path(path_str).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding=DEFAULT_ENCODING)
    return path


def load_lines(path_str: str) -> Iterable[str]:
    """Yield stripped lines from a file."""
    return (line.strip() for line in load_text(path_str).splitlines())
