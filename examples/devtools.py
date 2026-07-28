"""A realistic developer-tools module, of the kind you'd want an agent to use.

Nothing here knows that MCP exists. Point any2mcp at it:

    any2mcp examples/devtools.py --risk-report   # audit first, without importing
    any2mcp examples/devtools.py                 # serve the safe subset

Two of these functions are genuinely dangerous to hand to a language model.
Under the default `guard` policy they are not exposed, and you have to name them
explicitly to change that.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path


def word_count(text: str) -> dict[str, int]:
    """Count words, lines, and characters in a string.

    Pure computation - no side effects at all.
    """
    return {
        "words": len(text.split()),
        "lines": len(text.splitlines()),
        "characters": len(text),
    }


def read_project_file(path: str, max_bytes: int = 20_000) -> str:
    """Read a UTF-8 text file from disk, truncating past *max_bytes*."""
    content = Path(path).read_text(encoding="utf-8")
    if len(content) > max_bytes:
        return content[:max_bytes] + f"\n...<truncated at {max_bytes} bytes>"
    return content


def list_directory(path: str = ".") -> list[str]:
    """List the entries of a directory, sorted."""
    return sorted(os.listdir(path))


def write_note(path: str, text: str) -> int:
    """Write *text* to *path*, replacing any existing file. Returns bytes written."""
    target = Path(path)
    target.write_text(text, encoding="utf-8")
    return len(text.encode("utf-8"))


def parse_json_file(path: str) -> object:
    """Load and return the JSON value stored in a file."""
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def run_shell(command: str, timeout: float = 30.0) -> str:
    """Run a shell command and return its combined output.

    Handing this to a model is handing it your machine. any2mcp will not expose
    it unless you pass `--allow-tool run_shell` (or `--policy open`).
    """
    completed = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return completed.stdout + completed.stderr


def delete_path(path: str) -> str:
    """Recursively delete a file or directory.

    Also blocked by default: an agent that misreads an instruction here does
    unrecoverable damage.
    """
    target = Path(path)
    if target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()
    return f"deleted {target}"
