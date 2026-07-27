"""any2mcp — turn any Python module into an MCP server. No decorators required."""

from __future__ import annotations

__version__ = "0.1.0"

from .build import BuildResult, Skipped, build_server
from .discover import Discovered, DiscoveryError, discover_functions
from .loader import ModuleLoadError, load_module

__all__ = [
    "BuildResult",
    "Discovered",
    "DiscoveryError",
    "ModuleLoadError",
    "Skipped",
    "__version__",
    "build_server",
    "discover_functions",
    "load_module",
]
