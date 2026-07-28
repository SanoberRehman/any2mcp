"""any2mcp — turn any Python module into an MCP server. No decorators required."""

from __future__ import annotations

__version__ = "0.2.0"

from .audit import AuditLog
from .build import BuildResult, Skipped, build_server
from .discover import Discovered, DiscoveryError, discover_functions
from .loader import ModuleLoadError, load_module
from .policy import Decision, Policy, PolicyMode
from .risk import (
    Capability,
    Finding,
    FunctionRisk,
    RiskAnalysisError,
    RiskLevel,
    analyze,
    analyze_path,
    analyze_source,
)

__all__ = [
    "AuditLog",
    "BuildResult",
    "Capability",
    "Decision",
    "Discovered",
    "DiscoveryError",
    "Finding",
    "FunctionRisk",
    "ModuleLoadError",
    "Policy",
    "PolicyMode",
    "RiskAnalysisError",
    "RiskLevel",
    "Skipped",
    "__version__",
    "analyze",
    "analyze_path",
    "analyze_source",
    "build_server",
    "discover_functions",
    "load_module",
]
