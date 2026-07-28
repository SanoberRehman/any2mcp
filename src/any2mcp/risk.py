"""Static capability analysis: what side effects can this function reach?

The goal is a *risk signal*, not a security boundary. We parse the target
module's source and, for each candidate function, look for calls into the
standard library (and a few ubiquitous third-party clients) that touch the
filesystem, the network, subprocesses, or the dynamic-execution builtins.

Two properties make the result more trustworthy than a naive grep:

1. **Import aliases are resolved.** ``import subprocess as sp; sp.run(...)``
   and ``from os import system as sh; sh(...)`` are both detected, because we
   build an alias table from the module's own import statements rather than
   matching on surface text.
2. **Intra-module calls are followed.** If ``publish()`` calls a module-local
   ``_upload()`` that calls ``requests.post``, ``publish`` inherits NETWORK.
   Recursion is depth-limited and cycle-guarded.

Known and deliberate limits — see ``README.md``; ``tests/fixtures/evasive.py``
asserts them so they can never be quietly overstated:

* Indirection defeats it. ``getattr(os, "system")("rm -rf /")`` or a call
  through a dict of callables resolves to nothing and is reported SAFE.
* Only the target module's own source is followed. A call into a third-party
  helper is classified by that call's *name*, not by analyzing the dependency.
* ``from x import *`` cannot be resolved and is noted on the result.

Because of this, a SAFE classification means "no known-risky call was found",
never "this function is harmless". The enforcement layer in ``policy.py`` is
what actually blocks execution; this module only decides what to tell it.
"""

from __future__ import annotations

import ast
import enum
import inspect
from dataclasses import dataclass
from functools import cached_property
from types import ModuleType

_MAX_DEPTH = 6


class Capability(enum.Enum):
    """A category of observable side effect."""

    FS_READ = "fs-read"
    FS_WRITE = "fs-write"
    FS_DELETE = "fs-delete"
    NETWORK = "network"
    SUBPROCESS = "subprocess"
    DYNAMIC_EXEC = "dynamic-exec"
    ENV = "env"

    @property
    def level(self) -> RiskLevel:
        return _CAPABILITY_LEVEL[self]

    @property
    def describe(self) -> str:
        return _CAPABILITY_HELP[self]


class RiskLevel(enum.Enum):
    """How much damage the worst capability could plausibly do.

    ``UNKNOWN`` is deliberately ordered alongside ``HIGH``: if we could not
    read a function's source we do not get to call it safe.
    """

    SAFE = ("safe", 0)
    LOW = ("low", 1)
    MODERATE = ("moderate", 2)
    HIGH = ("high", 3)
    UNKNOWN = ("unknown", 3)

    def __init__(self, label: str, order: int) -> None:
        self.label = label
        self.order = order

    def __ge__(self, other: RiskLevel) -> bool:
        return self.order >= other.order

    def __gt__(self, other: RiskLevel) -> bool:
        return self.order > other.order

    def __le__(self, other: RiskLevel) -> bool:
        return self.order <= other.order

    def __lt__(self, other: RiskLevel) -> bool:
        return self.order < other.order

    @classmethod
    def parse(cls, text: str) -> RiskLevel:
        for member in cls:
            if member.label == text:
                return member
        valid = ", ".join(m.label for m in cls)
        raise ValueError(f"unknown risk level {text!r} (expected one of: {valid})")


_CAPABILITY_LEVEL = {
    Capability.FS_READ: RiskLevel.LOW,
    Capability.ENV: RiskLevel.LOW,
    Capability.NETWORK: RiskLevel.MODERATE,
    Capability.FS_WRITE: RiskLevel.MODERATE,
    Capability.FS_DELETE: RiskLevel.HIGH,
    Capability.SUBPROCESS: RiskLevel.HIGH,
    Capability.DYNAMIC_EXEC: RiskLevel.HIGH,
}

_CAPABILITY_HELP = {
    Capability.FS_READ: "reads files or directory listings",
    Capability.FS_WRITE: "creates or modifies files",
    Capability.FS_DELETE: "deletes files or directory trees",
    Capability.NETWORK: "makes outbound network requests",
    Capability.SUBPROCESS: "runs external commands",
    Capability.DYNAMIC_EXEC: "executes code or data built at runtime",
    Capability.ENV: "reads or mutates environment variables",
}

# Fully-qualified symbols, matched after alias resolution. High confidence.
_DOTTED: dict[str, Capability] = {}


def _register(capability: Capability, *symbols: str) -> None:
    for symbol in symbols:
        _DOTTED[symbol] = capability


_register(
    Capability.SUBPROCESS,
    "os.system",
    "os.popen",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.spawnl",
    "os.spawnv",
    "os.posix_spawn",
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "subprocess.Popen",
    "pty.spawn",
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
)
_register(
    Capability.FS_DELETE,
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.removedirs",
    "shutil.rmtree",
)
_register(
    Capability.FS_WRITE,
    "os.mkdir",
    "os.makedirs",
    "os.rename",
    "os.renames",
    "os.replace",
    "os.truncate",
    "os.chmod",
    "os.chown",
    "os.symlink",
    "os.link",
    "os.utime",
    "os.write",
    "shutil.copy",
    "shutil.copy2",
    "shutil.copyfile",
    "shutil.copytree",
    "shutil.move",
    "shutil.make_archive",
    "shutil.unpack_archive",
    "tempfile.mkstemp",
    "tempfile.mkdtemp",
    "tempfile.NamedTemporaryFile",
)
_register(
    Capability.FS_READ,
    "os.listdir",
    "os.scandir",
    "os.walk",
    "os.stat",
    "os.lstat",
    "os.readlink",
    "glob.glob",
    "glob.iglob",
    "shutil.disk_usage",
)
_register(
    Capability.NETWORK,
    "socket.socket",
    "socket.create_connection",
    "socket.gethostbyname",
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
    "http.client.HTTPConnection",
    "http.client.HTTPSConnection",
    "smtplib.SMTP",
    "smtplib.SMTP_SSL",
    "ftplib.FTP",
    "telnetlib.Telnet",
    "webbrowser.open",
    # Ubiquitous third-party clients. Matched by name only; we never import them.
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "requests.head",
    "requests.options",
    "requests.request",
    "requests.Session",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.patch",
    "httpx.delete",
    "httpx.head",
    "httpx.request",
    "httpx.stream",
    "httpx.Client",
    "httpx.AsyncClient",
    "aiohttp.ClientSession",
    "urllib3.PoolManager",
)
_register(
    Capability.DYNAMIC_EXEC,
    "importlib.import_module",
    "importlib.reload",
    "pickle.load",
    "pickle.loads",
    "marshal.load",
    "marshal.loads",
    "dill.loads",
    "yaml.unsafe_load",
    "yaml.load_all",
    "ctypes.CDLL",
    "ctypes.WinDLL",
)
_register(
    Capability.ENV,
    "os.getenv",
    "os.putenv",
    "os.unsetenv",
)

# Bare builtins, only when not shadowed by a module-level definition.
_BUILTINS: dict[str, Capability] = {
    "eval": Capability.DYNAMIC_EXEC,
    "exec": Capability.DYNAMIC_EXEC,
    "compile": Capability.DYNAMIC_EXEC,
    "__import__": Capability.DYNAMIC_EXEC,
}

# Method names whose receiver type we cannot infer. Lower confidence: a
# ``.write()`` may be a file, a socket, or an in-memory buffer. Reported as
# heuristic so the risk report can say so out loud.
_METHODS: dict[str, Capability] = {
    "write_text": Capability.FS_WRITE,
    "write_bytes": Capability.FS_WRITE,
    "writelines": Capability.FS_WRITE,
    "mkdir": Capability.FS_WRITE,
    "touch": Capability.FS_WRITE,
    "rename": Capability.FS_WRITE,
    "replace": Capability.FS_WRITE,
    "chmod": Capability.FS_WRITE,
    "unlink": Capability.FS_DELETE,
    "rmtree": Capability.FS_DELETE,
    "read_text": Capability.FS_READ,
    "read_bytes": Capability.FS_READ,
    "iterdir": Capability.FS_READ,
    "rglob": Capability.FS_READ,
}

# Attribute accesses that are risky without being calls, e.g. ``os.environ``.
_ATTRIBUTES: dict[str, Capability] = {
    "os.environ": Capability.ENV,
    "os.environb": Capability.ENV,
}

_WRITE_MODE_CHARS = frozenset("wax+")


@dataclass(frozen=True)
class Finding:
    """One risky construct found in (or reachable from) a function."""

    capability: Capability
    symbol: str
    lineno: int
    heuristic: bool = False
    via: str | None = None

    def render(self) -> str:
        text = f"{self.symbol} (line {self.lineno})"
        if self.via:
            text += f" via {self.via}()"
        if self.heuristic:
            text += " [heuristic]"
        return text


@dataclass(frozen=True)
class FunctionRisk:
    """The capability profile of a single function."""

    name: str
    findings: tuple[Finding, ...] = ()
    analyzed: bool = True
    note: str | None = None

    @cached_property
    def capabilities(self) -> frozenset[Capability]:
        return frozenset(f.capability for f in self.findings)

    @cached_property
    def level(self) -> RiskLevel:
        if not self.analyzed:
            return RiskLevel.UNKNOWN
        if not self.findings:
            return RiskLevel.SAFE
        return max((c.level for c in self.capabilities), key=lambda lv: lv.order)

    def findings_for(self, capability: Capability) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.capability is capability)


class RiskAnalysisError(Exception):
    """Raised when a target's source cannot be read or parsed."""


def analyze(module: ModuleType, names: list[str]) -> dict[str, FunctionRisk]:
    """Classify each function in *names* that is defined in *module*."""
    try:
        source = inspect.getsource(module)
    except (OSError, TypeError):
        return _all_unanalyzed(names, "source unavailable, cannot analyze")

    try:
        return analyze_source(source, names)
    except RiskAnalysisError as exc:  # pragma: no cover - already imported once
        return _all_unanalyzed(names, str(exc))


def analyze_source(
    source: str, names: list[str] | None = None
) -> dict[str, FunctionRisk]:
    """Classify functions in *source* without importing anything.

    When *names* is None the exposable set is derived statically, mirroring
    :mod:`any2mcp.discover`: ``__all__`` if it is a literal list of strings,
    otherwise every public top-level function.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise RiskAnalysisError(f"source failed to parse: {exc}") from exc

    analyzer = _ModuleAnalyzer(tree)
    if names is None:
        names = analyzer.static_function_names()
    return analyzer.analyze(names)


def analyze_path(path: str, names: list[str] | None = None) -> dict[str, FunctionRisk]:
    """Classify functions in a ``.py`` file **without importing it**.

    This is the important one for untrusted code: importing a module executes
    its top-level statements, so the risk report must not require it. It also
    means a module can be audited without its dependencies installed.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
    except OSError as exc:
        raise RiskAnalysisError(f"could not read {path!r}: {exc}") from exc
    return analyze_source(source, names)


def _all_unanalyzed(names: list[str], note: str) -> dict[str, FunctionRisk]:
    return {
        name: FunctionRisk(name=name, analyzed=False, note=note) for name in names
    }


class _ModuleAnalyzer:
    def __init__(self, tree: ast.Module) -> None:
        self._tree = tree
        self._aliases = _build_aliases(tree)
        self._star_import = any(
            isinstance(node, ast.ImportFrom)
            and any(a.name == "*" for a in node.names)
            for node in ast.walk(tree)
        )
        self._functions = _collect_functions(tree)
        self._shadowed = set(self._functions)
        self._cache: dict[str, tuple[Finding, ...]] = {}

    def static_function_names(self) -> list[str]:
        """The exposable function names, derived without importing.

        Mirrors :func:`any2mcp.discover.discover_functions`: a literal
        ``__all__`` wins, otherwise public top-level functions in source order.
        """
        declared = self._static_all()
        if declared is not None:
            return [n for n in declared if n in self._functions]
        return [n for n in self._functions if not n.startswith("_")]

    def _static_all(self) -> list[str] | None:
        for node in self._tree.body:
            if not isinstance(node, ast.Assign):
                continue
            if not any(
                isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets
            ):
                continue
            if not isinstance(node.value, ast.List | ast.Tuple):
                return None  # computed __all__; fall back to public defs
            items = [
                el.value
                for el in node.value.elts
                if isinstance(el, ast.Constant) and isinstance(el.value, str)
            ]
            return items
        return None

    def analyze(self, names: list[str]) -> dict[str, FunctionRisk]:
        results: dict[str, FunctionRisk] = {}
        note = (
            "module uses `from ... import *`; some symbols were unresolvable"
            if self._star_import
            else None
        )
        for name in names:
            node = self._functions.get(name)
            if node is None:
                results[name] = FunctionRisk(
                    name=name,
                    analyzed=False,
                    note="not defined at module level in this file",
                )
                continue
            findings = self._findings_for(name, depth=0, seen=set())
            results[name] = FunctionRisk(name=name, findings=findings, note=note)
        return results

    def _findings_for(
        self, name: str, *, depth: int, seen: set[str]
    ) -> tuple[Finding, ...]:
        if depth == 0 and name in self._cache:
            return self._cache[name]
        node = self._functions.get(name)
        if node is None or name in seen or depth > _MAX_DEPTH:
            return ()

        seen = seen | {name}
        findings: list[Finding] = []
        for child in ast.walk(node):
            findings.extend(self._inspect_node(child))
            # Follow calls into other module-level functions.
            if isinstance(child, ast.Call):
                callee = _bare_name(child.func)
                if callee and callee in self._functions and callee not in seen:
                    for inherited in self._findings_for(
                        callee, depth=depth + 1, seen=seen
                    ):
                        findings.append(
                            Finding(
                                capability=inherited.capability,
                                symbol=inherited.symbol,
                                lineno=inherited.lineno,
                                heuristic=inherited.heuristic,
                                via=inherited.via or callee,
                            )
                        )

        deduped = _dedupe(findings)
        if depth == 0:
            self._cache[name] = deduped
        return deduped

    def _inspect_node(self, node: ast.AST) -> list[Finding]:
        if isinstance(node, ast.Call):
            return self._inspect_call(node)
        if isinstance(node, ast.Attribute):
            dotted = self._resolve(node)
            capability = _ATTRIBUTES.get(dotted) if dotted else None
            if capability:
                return [Finding(capability, dotted, node.lineno)]
        return []

    def _inspect_call(self, node: ast.Call) -> list[Finding]:
        func = node.func

        if isinstance(func, ast.Name):
            name = func.id
            if name in self._shadowed:
                return []  # a module-local definition; handled transitively
            resolved = self._aliases.get(name)
            if resolved and resolved in _DOTTED:
                return [Finding(_DOTTED[resolved], resolved, node.lineno)]
            # open(...) — the mode argument decides read vs write.
            if name == "open":
                return [Finding(_open_capability(node), "open", node.lineno)]
            if name in _BUILTINS:
                return [Finding(_BUILTINS[name], name, node.lineno)]
            return []

        if isinstance(func, ast.Attribute):
            # Resolve the qualified name first: `webbrowser.open` is a network
            # call, not a file read, and must not be caught by the `.open` case.
            dotted = self._resolve(func)
            if dotted and dotted in _DOTTED:
                return [Finding(_DOTTED[dotted], dotted, node.lineno)]
            if func.attr == "open":  # e.g. Path(p).open("w") - mode comes first
                return [
                    Finding(
                        _open_capability(node, mode_index=0), ".open", node.lineno
                    )
                ]
            capability = _METHODS.get(func.attr)
            if capability:
                return [
                    Finding(
                        capability,
                        f".{func.attr}",
                        node.lineno,
                        heuristic=True,
                    )
                ]
        return []

    def _resolve(self, node: ast.Attribute) -> str | None:
        """Turn an attribute chain into a dotted path, applying import aliases."""
        dotted = _dotted_name(node)
        if dotted is None:
            return None
        head, _, tail = dotted.partition(".")
        target = self._aliases.get(head)
        if target is None:
            return dotted
        return f"{target}.{tail}" if tail else target


def _build_aliases(tree: ast.Module) -> dict[str, str]:
    """Map each locally-bound import name to its fully-qualified target."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    # `import os.path` binds the root package name `os`.
                    root = alias.name.split(".")[0]
                    aliases[root] = root
        elif isinstance(node, ast.ImportFrom):
            if node.level or node.module is None:
                continue  # relative import; out of scope
            for alias in node.names:
                if alias.name == "*":
                    continue
                bound = alias.asname or alias.name
                aliases[bound] = f"{node.module}.{alias.name}"
    return aliases


def _collect_functions(
    tree: ast.Module,
) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    found: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            found[node.name] = node  # later definition wins, as at runtime
    return found


def _open_capability(node: ast.Call, *, mode_index: int = 1) -> Capability:
    """Read the `mode` argument of an ``open`` call; assume write if unclear.

    ``mode_index`` differs by call form: the builtin is ``open(path, mode)`` but
    a bound ``Path(p).open(mode)`` puts the mode first.
    """
    mode: ast.expr | None = None
    if len(node.args) > mode_index:
        mode = node.args[mode_index]
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode = keyword.value
    if mode is None:
        return Capability.FS_READ
    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
        if _WRITE_MODE_CHARS & set(mode.value):
            return Capability.FS_WRITE
        return Capability.FS_READ
    # Mode computed at runtime — be conservative.
    return Capability.FS_WRITE


def _dotted_name(node: ast.expr) -> str | None:
    """``ast.Attribute`` chain -> ``"a.b.c"``, or None if not a pure chain."""
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return ".".join(reversed(parts))


def _bare_name(node: ast.expr) -> str | None:
    return node.id if isinstance(node, ast.Name) else None


def _dedupe(findings: list[Finding]) -> tuple[Finding, ...]:
    seen: set[tuple[Capability, str, int, str | None]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.capability, finding.symbol, finding.lineno, finding.via)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    unique.sort(key=lambda f: (-f.capability.level.order, f.lineno, f.symbol))
    return tuple(unique)
