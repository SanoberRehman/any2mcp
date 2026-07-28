"""Importable fixture with a spread of real capabilities (stdlib only).

Used to test policy enforcement end-to-end: unlike ``risky.py`` this module has
no third-party imports, so it can actually be loaded and served.
"""

import os
import shutil
import subprocess


def add(a: float, b: float) -> float:
    """Pure arithmetic. Should always be exposed."""
    return a + b


def read_file(path: str) -> str:
    """Read a file. Low risk."""
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def write_file(path: str, text: str) -> int:
    """Write a file. Moderate risk."""
    with open(path, "w", encoding="utf-8") as handle:
        return handle.write(text)


def list_env() -> list[str]:
    """Read environment variable names. Low risk."""
    return sorted(os.environ)


def run_command(cmd: str) -> str:
    """Execute a shell command. High risk: must be blocked by default."""
    return subprocess.check_output(cmd, shell=True, text=True)


def delete_tree(path: str) -> None:
    """Recursively delete a directory. High risk: must be blocked by default."""
    shutil.rmtree(path)


def evaluate(expression: str) -> object:
    """Evaluate a Python expression. High risk: must be blocked by default."""
    return eval(expression)


async def slow_double(value: float) -> float:
    """An async pure function, to prove wrapping preserves coroutines."""
    return value * 2
