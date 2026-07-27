# any2mcp

**Turn any Python module into an [MCP](https://modelcontextprotocol.io) server. No decorators, no boilerplate, no rewrites.**

[![CI](https://github.com/SanoberRehman/any2mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/SanoberRehman/any2mcp/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/any2mcp.svg)](https://pypi.org/project/any2mcp/)
[![Python](https://img.shields.io/pypi/pyversions/any2mcp.svg)](https://pypi.org/project/any2mcp/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

You have a file full of useful Python functions. You want an LLM agent to call them. Today that means importing an MCP framework, decorating every function, and wiring up a server.

`any2mcp` skips all of that. Point it at a module and **every public function becomes a fully-schematized MCP tool** — argument types, validation, and descriptions derived automatically from your type hints and docstrings.

```bash
any2mcp ./tools.py
```

That's the whole setup.

---

## The difference

**Before** — the standard way, one decorator per function, in a file that now depends on MCP:

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

**After** — your module stays plain Python, knows nothing about MCP:

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

---

## Install

```bash
pip install any2mcp
# or, with uv:
uv tool install any2mcp
```

## Quickstart

Inspect what would be exposed — no server needed:

```bash
any2mcp examples/calculator.py --list
```

Serve over stdio (what MCP clients expect):

```bash
any2mcp examples/calculator.py
```

Expose just one function, or filter with globs:

```bash
any2mcp calculator.py:add            # only `add`
any2mcp calculator.py --exclude '_*' # skip anything underscore-ish
any2mcp mypackage.tools              # a dotted, importable module works too
```

## See it actually work

`examples/demo_client.py` launches the server and calls it as a real MCP client would:

```console
$ python examples/demo_client.py

Tools exposed by calculator.py:
  - add: Add two numbers and return the sum.
  - divide: Divide ``a`` by ``b``. Raises if ``b`` is zero.
  - round_to: Round ``value`` to ``ndigits`` decimal places using the given mode.
  - summarize: Return count, sum, and mean of ``numbers``, with an optional label.

Calling add(a=2, b=3):
  -> 5.0

Calling summarize(numbers=[10, 20, 30], label='scores'):
  -> { "count": 3, "sum": 60.0, "mean": 20.0, "label": "scores" }
```

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

## Use it with Claude Desktop (or any MCP client)

Add to your client's MCP config:

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

## Which functions get exposed?

Resolved in this order:

1. A `:selector` (`tools.py:add`) exposes exactly that one function.
2. Otherwise, if the module defines `__all__`, that list is the allow-list.
3. Otherwise, every public function (no leading underscore) **defined in the module** — functions merely imported into it are skipped, so `from os.path import join` won't leak in as a tool.

`--include` / `--exclude` glob patterns are applied on top.

## Security

Importing a module runs its top-level code, and every exposed function becomes callable by an LLM. `any2mcp` does not sandbox anything — **only point it at code you trust**, exactly as you would with `python -c "import that_module"`. Prefer `__all__` or `--include` to keep the exposed surface intentional.

## Roadmap

- [ ] Expose class methods and `@staticmethod`s
- [ ] Resources & prompts, not just tools
- [ ] `--dry-run` schema linting for CI
- [ ] Config file for per-tool renaming / descriptions

OpenAPI and FastAPI conversion are intentionally **out of scope** — [`fastmcp`](https://github.com/jlowin/fastmcp) already does those well. `any2mcp` focuses on the gap it leaves: plain modules, zero decoration.

## Development

```bash
uv sync
uv run pytest        # 33 tests, incl. an end-to-end client call
uv run ruff check .
```

## License

MIT — see [LICENSE](LICENSE).
