# any2mcp

**Turn any Python module into an [MCP](https://modelcontextprotocol.io) server — without handing a language model your shell.**

[![CI](https://github.com/SanoberRehman/any2mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/SanoberRehman/any2mcp/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/any2mcp.svg)](https://pypi.org/project/any2mcp/)
[![Python](https://img.shields.io/pypi/pyversions/any2mcp.svg)](https://pypi.org/project/any2mcp/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

You have a file full of useful Python functions and you want an agent to call them. Today that means importing an MCP framework and decorating every function — so your business logic now depends on MCP.

`any2mcp` skips that. Point it at a module and **every public function becomes a fully-schematized MCP tool**, with argument types and descriptions derived from the type hints and docstrings you already wrote:

```bash
any2mcp ./tools.py
```

But "expose every function" is a dangerous default, and most MCP tooling stops there. If your module happens to contain a `run_shell()` or a `delete_path()`, that naive approach just gave a language model your machine.

So `any2mcp` reads your code before it exposes it:

```console
$ any2mcp examples/devtools.py --risk-report

any2mcp risk report: examples/devtools.py
policy: guard (allows up to 'moderate')

  RISK      TOOL               CAPABILITIES  STATUS
  --------  -----------------  ------------  -------
  safe      word_count         -             exposed
  low       read_project_file  fs-read       exposed
      - .read_text (line 36) [heuristic]
  low       list_directory     fs-read       exposed
      - os.listdir (line 44)
  moderate  write_note         fs-write      exposed
      - .write_text (line 50) [heuristic]
  low       parse_json_file    fs-read       exposed
      - open (line 56)
  high      run_shell          subprocess    BLOCKED
      - subprocess.run (line 66)
      ! blocked: risk 'high' (subprocess) exceeds policy 'guard' (max 'moderate')
  high      delete_path        fs-delete     BLOCKED
      - shutil.rmtree (line 85)
      - .unlink (line 87) [heuristic]
      ! blocked: risk 'high' (fs-delete) exceeds policy 'guard' (max 'moderate')

5 exposed, 2 blocked.
```

The two dangerous functions are **not exposed**, and no flags were needed to get that.

---

## The difference

**Before** — one decorator per function, in a file that now depends on MCP:

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("calculator")

@mcp.tool()
def add(a: float, b: float) -> float:
    """Add two numbers."""
    return a + b

@mcp.tool()
def divide(a: float, b: float) -> float:
    """Divide a by b."""
    return a / b

# ...repeat for every function, forever

if __name__ == "__main__":
    mcp.run()
```

**After** — your module stays plain Python and knows nothing about MCP:

```python
# calculator.py — no imports, no decorators
def add(a: float, b: float) -> float:
    """Add two numbers."""
    return a + b

def divide(a: float, b: float) -> float:
    """Divide a by b."""
    return a / b
```

```bash
any2mcp calculator.py
```

## Install

```bash
pip install any2mcp
# or, with uv:
uv tool install any2mcp
```

> Not yet on PyPI? Install straight from source:
> `uv tool install "git+https://github.com/SanoberRehman/any2mcp"`

## Quickstart

```bash
any2mcp tools.py --risk-report       # audit what each function can reach
any2mcp tools.py --list              # show the exposed tools + JSON schemas
any2mcp tools.py                     # serve over stdio
any2mcp tools.py:add                 # expose only `add`
any2mcp tools.py --exclude '_*'      # filter with globs
any2mcp mypackage.tools              # a dotted, importable module works too
```

## The safety model

This is the part worth reading carefully, because the guarantees are uneven and it matters which is which.

### What is enforced

**A blocked function is never registered as a tool.** It is absent from `tools/list`, so the model cannot see it, cannot call it, and cannot talk its way past it. There is no confirmation token to forge and no runtime check to race — the tool simply does not exist on the server.

You can watch this happen against a real MCP client:

```console
$ python examples/demo_safety.py

=== any2mcp devtools.py (default policy: guard) ===
tools visible to the model: ['word_count', 'read_project_file', 'list_directory', 'write_note', 'parse_json_file']
  run_shell: withheld; calling it anyway -> Unknown tool: run_shell
  delete_path: withheld; calling it anyway -> Unknown tool: delete_path
  word_count still works -> {"words": 3, "lines": 1, "characters": 18}
```

### What is a heuristic

**Which functions get classified as risky.** `any2mcp` parses your module and looks for calls that reach the filesystem, the network, subprocesses, or the dynamic-execution builtins. It resolves import aliases, so both of these are caught:

```python
import subprocess as sp
def a(cmd): sp.run(cmd)              # -> subprocess (high)

from os import system as sh
def b(cmd): sh(cmd)                  # -> subprocess (high)
```

and it follows calls within your module, so a wrapper inherits its helper's capabilities:

```python
def _upload(data): requests.post("https://...", data=data)
def publish(data): _upload(data)     # -> network, "via _upload()"
```

But **static analysis is not sound, and indirection defeats it**:

```python
def sneaky(cmd):
    getattr(os, "system")(cmd)       # -> reported SAFE. Not detected.
```

So a `safe` classification means *"no known-risky call was found"*, never *"this function is harmless"*. These blind spots are asserted in [`tests/test_risk.py`](tests/test_risk.py) under `TestDocumentedBlindSpots`, so this claim cannot quietly drift into implying more than it should.

### What it is not

**`any2mcp` is not a sandbox.** Tools that *are* exposed run in-process with your full privileges. The policy decides what gets offered to a model; it does not contain what happens next.

Importing a module also executes its top-level code. That is why **`--risk-report` never imports a file target** — it works from source, so you can audit code before running any of it, and even audit a module whose dependencies you don't have installed.

### Policies

| Policy | Allows | Use it when |
|---|---|---|
| `open` | everything | You have read the code and want the 0.1 behaviour. |
| `guard` **(default)** | up to `moderate` — reads, writes, network | General use. Blocks subprocesses, `eval`, recursive deletes, and anything unanalyzable. |
| `readonly` | up to `low` — reads, env | The agent should look but not touch. |
| `strict` | `safe` only | Pure computation, no side effects of any kind. |

Overrides, in order of precedence — naming a specific tool beats a category rule, and an explicit deny always wins:

```bash
any2mcp tools.py --deny-tool 'admin_*'        # never expose these
any2mcp tools.py --allow-tool run_shell       # expose this one on purpose
any2mcp tools.py --deny-capability network    # block a whole capability
```

Capabilities are `fs-read`, `fs-write`, `fs-delete`, `network`, `subprocess`, `dynamic-exec`, and `env`.

### Use it as a CI gate

`--risk-report` exits **3** when anything is blocked and **0** when nothing is, so it can fail a build if someone adds a `subprocess` call to a module you expose to agents:

```yaml
- run: any2mcp src/agent_tools.py --risk-report --format json
```

### Audit log

```bash
any2mcp tools.py --audit-log calls.jsonl
```

Every call is appended as one JSON object. **Argument names and types are recorded; values are not** — tool arguments routinely carry API keys and file contents, and a log that silently copied them to disk would be its own vulnerability. Opt in with `--audit-values` when you've decided that's appropriate for your data.

```jsonc
{"ts": "2026-07-28T05:45:14.604+00:00", "event": "blocked", "tool": "run_shell",
 "risk": "high", "reason": "risk 'high' (subprocess) exceeds policy 'guard' (max 'moderate')"}
{"ts": "2026-07-28T05:45:14.612+00:00", "event": "call", "tool": "write_note",
 "risk": "moderate", "duration_ms": 0.431, "ok": true,
 "args": {"path": "str", "text": "str"}}
{"ts": "2026-07-28T05:45:14.614+00:00", "event": "call", "tool": "word_count",
 "risk": "safe", "duration_ms": 0.003, "ok": true, "args": {"text": "str"}}
```

Blocked tools are recorded too, so the log shows what was withheld, not just what ran.

## Rich schemas, for free

`any2mcp` doesn't invent its own type system — it hands each function to the MCP SDK's pydantic machinery, the same code path the official `@tool` decorator uses. So the hard cases just work: `Optional[...]`, unions, `Enum`, `Literal`, `list`/`dict`/`tuple`, pydantic models and dataclasses as parameters, defaults, and `async def`.

```jsonc
// any2mcp calculator.py --list  (excerpt for round_to)
{
  "name": "round_to",
  "input_schema": {
    "properties": {
      "value":   { "type": "number" },
      "ndigits": { "type": "integer", "default": 2 },
      "mode":    { "$ref": "#/$defs/Rounding", "default": "nearest" }
    },
    "$defs": { "Rounding": { "enum": ["up", "down", "nearest"], "type": "string" } },
    "required": ["value"]
  }
}
```

A function whose signature genuinely can't be schematized is skipped with a message on stderr — one unsupported function costs one tool, never the whole server.

## Use it with Claude Desktop (or any MCP client)

```jsonc
{
  "mcpServers": {
    "my-tools": {
      "command": "any2mcp",
      "args": ["/absolute/path/to/tools.py"]
    }
  }
}
```

Add `"--policy", "readonly"` to the `args` array to tighten it further.

## Which functions get exposed?

Resolved in this order:

1. A `:selector` (`tools.py:add`) exposes exactly that one function.
2. Otherwise, if the module defines `__all__`, that list is the allow-list.
3. Otherwise, every public function (no leading underscore) **defined in the module** — functions merely imported into it are skipped, so `from os.path import join` won't leak in as a tool.

`--include` / `--exclude` globs apply on top, then the policy decides what survives.

## Roadmap

- [ ] Policy file (`any2mcp.toml`) so per-tool decisions can be reviewed in git
- [ ] Expose class methods and `@staticmethod`s
- [ ] Resources & prompts, not just tools
- [ ] Taint tracking, to tell `read_file("/etc/passwd")` from `read_file(user_path)`

OpenAPI and FastAPI conversion are intentionally **out of scope** — [`fastmcp`](https://github.com/jlowin/fastmcp) already does those well. `any2mcp` focuses on the gap they leave: plain modules, zero decoration, and a defensible answer to "what did I just expose?"

## Development

```bash
uv sync
uv run pytest        # 127 tests, incl. real MCP client sessions
uv run ruff check .
```

## License

MIT — see [LICENSE](LICENSE).
