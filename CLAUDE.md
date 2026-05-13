# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install runtime dependency
pip install -r requirements.txt

# Install dev tools (ruff, mypy, types-requests)
pip install -r requirements-dev.txt

# Lint
ruff check .

# Type check (non-blocking; mypy errors are warnings only)
mypy --ignore-missing-imports *.py

# Compile check (no test suite — CI uses this instead)
python -m compileall -q .
```

There are no automated tests. CI runs `ruff check`, `python -m compileall`, and `mypy` (continue-on-error).

## Architecture

The tool monitors PyPI and npm for new releases of the top N packages, diffs each release against its predecessor, runs the diff through Cursor Agent CLI for LLM analysis, and fires a Slack alert for malicious findings.

### Module responsibilities

| File | Role |
|------|------|
| `monitor.py` | Main orchestrator — spawns one daemon thread per ecosystem, each running its own poll loop |
| `package_diff.py` | Downloads two versions from PyPI/npm registry APIs (no pip/npm required) and generates a unified diff markdown report |
| `analyze_diff.py` | Invokes the `agent` CLI (`--mode ask --trust`) and parses the `Verdict: malicious/benign` line from its output |
| `slack.py` | Slack bot client — reads credentials from `etc/slack.json` (gitignored, must be created manually) |
| `top_pypi_packages.py` | Fetches top PyPI packages from the hugovk dataset |
| `pypi_monitor.py` | Standalone PyPI changelog poller (no analysis, useful for exploring release velocity) |

### Data flow

1. **PyPI thread**: `changelog_since_serial()` → filter watchlist → `diff_package()` → `analyze_report()` → optional Slack alert
2. **npm thread**: CouchDB `_changes` feed → filter watchlist → `npm_diff_package()` → `analyze_report()` → optional Slack alert
3. Both threads call the same `analyze_report()` / `send_slack_alert()` functions from `monitor.py`

### State persistence (`last_serial.yaml`)

Persists the PyPI changelog serial and npm CouchDB sequence + epoch between restarts. Written by a hand-rolled sectioned-YAML writer (no PyYAML dependency); mutations are guarded by `_state_lock`. File is gitignored — if absent, the monitor starts from the registry head.

### Archive handling (`package_diff.py`)

- PyPI: prefers pure-Python universal wheel (`py3-none-any`); diffs both wheel **and** sdist when both exist (so attacks hidden in only one artifact type are caught)
- npm: downloads tarballs directly from the registry
- `extract_archive()` blocks path-traversal via `_safe_tar_members` / `_safe_zip_members`; uses `zlib` decompression directly instead of `gzip.GzipFile` to avoid a CPython 3.9 `_PaddedFile` bug

### LLM analysis (`analyze_diff.py`)

Writes an `instructions.md` into the same workspace directory as the diff file, then runs:

```
agent "Follow instructions.md" -p --mode ask --trust --workspace <dir> [--model <model>]
```

The agent binary is located via `shutil.which("agent")` with a fallback to `~/AppData/Local/cursor-agent/agent.cmd` on Windows. Default model is `composer-2-fast`; override with `--model`.

### Slack configuration

Create `etc/slack.json` (gitignored):

```json
{
    "url": "https://hooks.slack.com/services/...",
    "bot_token": "xoxb-...",
    "channel": "C01XXXXXXXX"
}
```

The `Slack` class is instantiated per-alert in `send_slack_alert()` and requires `chat:write` scope.
