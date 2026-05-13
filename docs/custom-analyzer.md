# Adding a Custom Analyzer Backend

The monitor ships with two LLM backends (`cursor`, `claude-code`) but anything that runs from a CLI, accepts a prompt, and prints to stdout can be plugged in — OpenCode, Aider, Codex CLI, Gemini CLI, a local Ollama wrapper, or your own home-grown agent.

This guide walks through what an analyzer *is* in this project, the non-negotiable safety contract, and how to register a new one.

---

## Why this works

Every analyzer does the same three things:

1. **Receive a workspace** — a temp directory containing a `<package>_diff.md` file and an `instructions.md` telling the agent what to do.
2. **Run the LLM with read-only tools** so it can `Read` / `Grep` / `Glob` the diff but cannot execute code from it.
3. **Print a verdict line to stdout** that matches `Verdict: malicious|benign`.

Step 1 and step 3 are the same for every backend. Step 2 — the subprocess invocation — is the only thing that varies. That's exactly what the `Analyzer` registry abstracts.

---

## ⚠️ The safety contract (non-negotiable)

The diff being reviewed **may contain real malicious code**. If your analyzer can be tricked into executing any of it, you've turned a security tool into a malware-delivery vehicle.

Your `build_command` MUST enforce, at minimum:

- **No shell / Bash / subprocess execution** by the agent.
- **No file writes** (no Edit, Write, NotebookEdit, or equivalent).
- **No network tools** that fetch URLs from the diff (e.g. arbitrary `curl`-like tools the LLM can call).

How you enforce this is backend-specific:

| Backend | Enforcement |
|---------|-------------|
| Cursor Agent | `--mode ask --trust` (ask mode is read-only) |
| Claude Code | `--tools "Read,Grep,Glob" --permission-mode plan` (restricts tool universe + blocks side effects) |
| Your backend | Whatever flag(s) your CLI offers — `--read-only`, `--no-tools`, a tool allowlist, etc. |

**If your CLI has no read-only mode, do not integrate it.** No exceptions. Run it in a disposable VM or container instead, then integrate the containerised version.

A secondary defence-in-depth recommendation: run the subprocess inside a sandbox (Linux: `firejail`, `bwrap`, or a rootless container; macOS: `sandbox-exec`; Windows: a low-integrity AppContainer). The monitor doesn't ship sandboxing — but you can wrap your backend's binary in a sandbox script and point `find_binary` at the wrapper.

---

## The `Analyzer` interface

Defined in `analyze_diff.py`:

```python
@dataclass(frozen=True)
class Analyzer:
    name: str
    find_binary: Callable[[], str]
    build_command: Callable[[str, Path, str | None], list[str]]
    default_model: str | None = None
    timeout: int = 300
```

| Field | Purpose |
|-------|---------|
| `name` | The string passed to `--analyzer`. Must be unique. |
| `find_binary` | A zero-arg callable that returns the absolute path to the CLI binary, or raises `FileNotFoundError` with install instructions. |
| `build_command` | Builds the argv for `subprocess.run`. Signature: `(binary, diff_file, model) -> list[str]`. **This is where the read-only flags go.** |
| `default_model` | Model string used when the user doesn't pass `--model`. `None` means "let the backend pick". |
| `timeout` | Subprocess timeout in seconds. Default 300. Increase for slow local models. |

Two things the dispatcher does *for* you:

- Writes `instructions.md` into the workspace (the diff's parent dir) before invocation.
- Runs the subprocess with `cwd=workspace`, captures stdout/stderr as UTF-8, treats any non-zero exit as `verdict=unknown`.

Your `build_command` does **not** need to handle cwd, the instructions file, or output capture.

---

## Step-by-step: registering a new analyzer

### 1. Write a `find_binary` function

```python
def _find_myagent() -> str:
    found = shutil.which("myagent")
    if found:
        return found
    # Add platform-specific fallbacks if your installer drops the binary
    # somewhere not on PATH (Windows AppData, ~/.local/bin, etc.)
    if platform.system() == "Windows":
        candidate = Path.home() / "AppData/Local/myagent/myagent.exe"
        if candidate.exists():
            return str(candidate)
    raise FileNotFoundError(
        "myagent CLI not found. Install with: <one-liner install command>"
    )
```

### 2. Write a `build_command` function

This is the load-bearing part. It must:

- Pass the prompt `"Follow instructions.md"` (or a backend-specific equivalent that reads the file).
- Run in non-interactive / single-shot mode (most CLIs use `-p`, `--print`, `--non-interactive`, or `--oneshot`).
- Apply read-only / no-tools flags (see safety section above).
- Append `--model <name>` only if `model` is truthy.

```python
def _build_myagent_cmd(binary: str, diff_file: Path, model: str | None) -> list[str]:
    cmd = [
        binary,
        "Follow instructions.md",
        "--print",            # non-interactive
        "--read-only",        # YOUR backend's read-only flag(s) — required
        "--workspace", str(diff_file.parent.resolve()),
    ]
    if model:
        cmd.extend(["--model", model])
    return cmd
```

Whether you pass `--workspace` explicitly depends on whether your CLI honors cwd or needs an explicit path. The dispatcher always sets `cwd=workspace`, so either works.

### 3. Register it

Add one entry to the `ANALYZERS` dict in `analyze_diff.py`:

```python
ANALYZERS: dict[str, Analyzer] = {
    "cursor": Analyzer(...),
    "claude-code": Analyzer(...),
    "myagent": Analyzer(
        name="myagent",
        find_binary=_find_myagent,
        build_command=_build_myagent_cmd,
        default_model=None,        # or "myagent-base" etc.
        timeout=300,
    ),
}
```

That's it. Both CLIs (`monitor.py --analyzer myagent` and `analyze_diff.py --analyzer myagent`) pick it up automatically because their argparse `choices` are built from `sorted(ANALYZERS)`.

### 4. Test

```bash
# Generate a known-benign diff
python3 package_diff.py requests 2.31.0 2.32.0 -o /tmp/requests_diff.md

# Run your analyzer against it
python3 analyze_diff.py /tmp/requests_diff.md --analyzer myagent
```

Expect:
- Exit code `0` (benign), `1` (malicious), or `2` (unknown/error).
- Stdout starting with `Verdict: benign` and a short explanation.

If you get `Verdict: UNKNOWN`, your subprocess exited non-zero or produced no parseable verdict line. Re-run with `--debug` (via `monitor.py`) or wrap your command in a print to inspect what the binary actually emitted.

---

## What `instructions.md` looks like

The dispatcher writes this file into the workspace before invoking your binary (template in `analyze_diff.py:INSTRUCTIONS_TEMPLATE`):

```markdown
# Supply Chain Diff Review

Review the diff in `<package>_diff.md` and determine if the changes are highly
likely to show evidence of a supply chain compromise.

## Response format

Start your response with exactly one of these lines:

    Verdict: malicious
    Verdict: benign

Then explain your reasoning briefly.

## What to look for
- Obfuscated code (base64, exec, eval, XOR, encoded strings)
- Network calls to unexpected hosts
- File system writes to startup/persistence locations
- Process spawning, shell commands
- Steganography or data hiding in media files
- Credential/token exfiltration
- Typosquatting indicators
- Suspicious npm lifecycle scripts (preinstall/install/postinstall)
- Dynamic require()/import() of obfuscated or encoded URLs
- Minified or bundled payloads added outside normal build artifacts

Only report "malicious" if you are highly confident.
```

Your agent should be able to **read** that file from the current working directory. Most coding-agent CLIs do this naturally because they treat the workspace as their root.

If your CLI doesn't read files from disk (e.g. it only takes a prompt argument), you have two options:

- **Inline the prompt**: have `build_command` read `instructions.md` itself and pass the contents as the prompt. The dispatcher has already written it by the time `build_command` runs.
- **Use stdin**: return a command list and use the `input=` parameter of `subprocess.run`. The current dispatcher doesn't support stdin — you'd need a small extension (see "Going further" below).

---

## Worked example: a hypothetical OpenCode-style backend

OpenCode (https://github.com/sst/opencode) is an open-source coding agent with a CLI. The exact flags below are illustrative — check `opencode --help` for the current syntax.

```python
def _find_opencode() -> str:
    found = shutil.which("opencode")
    if found:
        return found
    raise FileNotFoundError(
        "opencode CLI not found. Install: curl -fsSL https://opencode.ai/install | bash"
    )


def _build_opencode_cmd(binary: str, diff_file: Path, model: str | None) -> list[str]:
    cmd = [
        binary,
        "run",                       # non-interactive / single-shot mode
        "Follow instructions.md",
        "--read-only",               # MUST enforce read-only — adversarial input
    ]
    if model:
        cmd.extend(["--model", model])
    return cmd


ANALYZERS["opencode"] = Analyzer(
    name="opencode",
    find_binary=_find_opencode,
    build_command=_build_opencode_cmd,
    default_model=None,
    timeout=300,
)
```

Then:

```bash
python3 analyze_diff.py /tmp/requests_diff.md --analyzer opencode
```

If OpenCode doesn't have a `--read-only` flag, you must either find equivalent restriction flags (a tool allowlist, a permission mode, etc.) or skip the integration. Do not rationalize unsafe defaults.

---

## Common pitfalls

| Symptom | Cause |
|---------|-------|
| `Verdict: UNKNOWN` on every run | Subprocess exited non-zero. Run the exact `build_command` argv manually in a shell to see the error. |
| Verdict parses but is always wrong | Model is too small / your prompt is being truncated. Try a larger model or trim the diff in `package_diff.py`. |
| Timeout after exactly 300s | Increase `timeout` on your `Analyzer` entry. Local models often need 600–1200s. |
| Agent tries to run code from the diff | Read-only flags are missing or wrong. **Stop and fix this before continuing.** |
| Works in PATH but `find_binary` fails | The CLI is on PATH for your interactive shell but not for the Python process. Add an explicit path fallback or set `PATH` in your env. |
| Auth prompt appears on first run | Your CLI is interactive on first auth. Authenticate it manually once (e.g. `myagent login`) before the monitor runs. |
| Different output between manual and monitor runs | The monitor runs with `cwd=workspace`, not your shell's cwd. Make sure your CLI handles that correctly. |

---

## Going further

The current dispatcher is intentionally minimal. If you need more control, edit `run_analyzer` in `analyze_diff.py`:

- **Stdin prompt**: pass `input=instructions_text, capture_output=True` to `subprocess.run`.
- **Env vars**: pass `env={**os.environ, "MY_API_KEY": ...}`. Better still, document the env var the user needs to set themselves.
- **Streaming output**: switch from `subprocess.run` to `subprocess.Popen` with line-by-line reads. Useful for very long analyses.
- **Per-analyzer instructions template**: add an `instructions_template: str` field to `Analyzer` and have the dispatcher pick the right one before calling `_write_instructions`.

Any of these are 10–20 lines of code. Keep them small; resist the urge to invent a plugin system.

---

## Checklist before opening a PR

- [ ] `find_binary` raises `FileNotFoundError` with a working install command.
- [ ] `build_command` enforces read-only (no Bash/Edit/Write/network).
- [ ] Manual test with `python3 package_diff.py requests 2.31.0 2.32.0 -o /tmp/r.md && python3 analyze_diff.py /tmp/r.md --analyzer <yours>` returns `Verdict: benign`.
- [ ] `ruff check .` and `python -m compileall -q .` pass.
- [ ] README "Prerequisites" section mentions your backend if it needs a non-obvious install step.
- [ ] No real credentials in code or tests — only env vars or `etc/` files (which are gitignored).
