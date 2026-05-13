# Copyright 2026 Elastic N.V.
# Licensed under the MIT License. See LICENSE file in the project root for details.

"""
Analyze a package diff report for supply chain compromise using Cursor Agent CLI
or Claude Code CLI.

Takes a diff markdown file (output of package_diff.py) and returns a verdict
of "malicious" or "benign" with supporting analysis.

Usage:
    python analyze_diff.py <diff_file>
    python analyze_diff.py telnyx_diff.md
    python analyze_diff.py telnyx_diff.md --model claude-sonnet-4-6 --analyzer claude-code
    python analyze_diff.py telnyx_diff.md --json

Can also be chained with package_diff.py:
    python package_diff.py requests 2.31.0 2.32.0 -o diff.md && python analyze_diff.py diff.md
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

log = logging.getLogger("monitor.analyze")

INSTRUCTIONS_TEMPLATE = """\
# Supply Chain Diff Review

Review the diff in `{diff_file}` and determine if the changes are highly likely
to show evidence of a supply chain compromise.

## Response format

Start your response with exactly one of these lines:

    Verdict: malicious
    Verdict: benign

Then explain your reasoning briefly.

## What to look for

- Obfuscated code (base64, exec, eval, XOR, encoded strings)
- Network calls to unexpected hosts (non-package-related URLs)
- File system writes to startup/persistence locations
- Process spawning, shell commands
- Steganography or data hiding in media files
- Credential/token exfiltration
- Typosquatting indicators
- Suspicious npm lifecycle scripts (preinstall, install, postinstall) in package.json
- Dynamic require() or import() of obfuscated or encoded URLs
- Minified or bundled payloads added outside normal build artifacts

Only report "malicious" if you are highly confident malicious code has been added.
"""


def _find_agent() -> str:
    agent = shutil.which("agent")
    if agent:
        return agent
    if platform.system() == "Windows":
        candidate = Path.home() / "AppData/Local/cursor-agent/agent.cmd"
        if candidate.exists():
            return str(candidate)
    raise FileNotFoundError(
        "Cursor Agent CLI not found. Install with: "
        "irm 'https://cursor.com/install?win32=true' | iex"
    )


def _find_claude_code() -> str:
    cc = shutil.which("claude")
    if cc:
        return cc
    if platform.system() == "Windows":
        for candidate in (
            Path.home() / ".local/bin/claude.exe",
            Path.home() / "AppData/Roaming/npm/claude.cmd",
        ):
            if candidate.exists():
                return str(candidate)
    raise FileNotFoundError(
        "Claude Code CLI not found. Install from https://claude.ai/code"
    )


def _write_instructions(workspace: Path, diff_file_name: str) -> None:
    (workspace / "instructions.md").write_text(
        INSTRUCTIONS_TEMPLATE.format(diff_file=diff_file_name),
        encoding="utf-8",
    )


@dataclass(frozen=True)
class Analyzer:
    """Definition of an LLM analyzer backend.

    ``build_command`` returns the argv to execute. It is responsible for
    enforcing read-only access — the diff under review may contain adversarial
    code, so no Bash/Edit/Write/network tools should be granted. The subprocess
    is always run with ``cwd=workspace`` (the diff's parent directory).

    See ``docs/custom-analyzer.md`` for the full integration guide.
    """
    name: str
    find_binary: Callable[[], str]
    build_command: Callable[[str, Path, "str | None"], list[str]]
    default_model: "str | None" = None
    timeout: int = 300


def _build_cursor_cmd(binary: str, diff_file: Path, model: "str | None") -> list[str]:
    # Read-only via `--mode ask --trust` (ask mode disallows edits).
    cmd = [
        binary,
        "Follow instructions.md",
        "-p",
        "--mode", "ask",
        "--trust",
        "--workspace", str(diff_file.parent.resolve()),
    ]
    if model:
        cmd.extend(["--model", model])
    return cmd


def _build_claude_code_cmd(binary: str, diff_file: Path, model: "str | None") -> list[str]:
    # Read-only via `--tools "Read,Grep,Glob"` (no Bash/Edit/Write) plus
    # `--permission-mode plan` (blocks side effects). Both flags are load-bearing.
    cmd = [
        binary,
        "-p", "Follow instructions.md",
        "--tools", "Read,Grep,Glob",
        "--permission-mode", "plan",
    ]
    if model:
        cmd.extend(["--model", model])
    return cmd


ANALYZERS: dict[str, Analyzer] = {
    "cursor": Analyzer(
        name="cursor",
        find_binary=_find_agent,
        build_command=_build_cursor_cmd,
        default_model="composer-2-fast",
    ),
    "claude-code": Analyzer(
        name="claude-code",
        find_binary=_find_claude_code,
        build_command=_build_claude_code_cmd,
        default_model=None,
    ),
}


def run_analyzer(
    diff_file: Path, analyzer: str = "cursor", model: "str | None" = None
) -> str:
    """Dispatch to the analyzer registered under *analyzer* and return stdout.

    Returns the empty string on non-zero exit (treated as ``verdict=unknown``
    by ``parse_verdict``).
    """
    if analyzer not in ANALYZERS:
        raise ValueError(
            f"Unknown analyzer: {analyzer!r}. Available: {sorted(ANALYZERS)}"
        )
    spec = ANALYZERS[analyzer]
    binary = spec.find_binary()
    workspace = diff_file.parent.resolve()
    _write_instructions(workspace, diff_file.name)

    effective_model = model or spec.default_model
    cmd = spec.build_command(binary, diff_file, effective_model)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=spec.timeout,
        cwd=str(workspace),
    )

    log.debug("%s stdout:\n%s", spec.name, result.stdout or "(empty)")
    log.debug("%s stderr:\n%s", spec.name, result.stderr or "(empty)")

    if result.returncode != 0:
        log.error("%s exited %d: %s", spec.name, result.returncode, result.stderr)
        return ""

    return result.stdout or ""


def parse_verdict(output: str) -> tuple[str, str]:
    """Extract verdict and reasoning from analyzer output."""
    verdict = "unknown"
    match = re.search(r"[Vv]erdict:\s*(malicious|benign)", output, re.IGNORECASE)
    if match:
        verdict = match.group(1).lower()
    return verdict, output.strip()


def main():
    parser = argparse.ArgumentParser(
        description="Analyze a package diff for supply chain compromise via Cursor Agent or Claude Code",
    )
    parser.add_argument("diff_file", type=Path, help="Path to diff markdown file (from package_diff.py)")
    parser.add_argument("--model", help="Model to use (cursor default: composer-2-fast)")
    parser.add_argument(
        "--analyzer", choices=sorted(ANALYZERS), default="cursor",
        help="LLM backend to use for analysis (default: cursor)",
    )
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output as JSON")
    args = parser.parse_args()

    if not args.diff_file.exists():
        parser.error(f"File not found: {args.diff_file}")

    print(f"[*] Analyzing {args.diff_file.name} with {args.analyzer}...", file=sys.stderr)

    raw_output = run_analyzer(args.diff_file, analyzer=args.analyzer, model=args.model)
    verdict, analysis = parse_verdict(raw_output)

    if args.json_output:
        print(json.dumps({
            "file": str(args.diff_file),
            "verdict": verdict,
            "analysis": analysis,
        }, indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"  FILE:    {args.diff_file.name}")
        print(f"  VERDICT: {verdict.upper()}")
        print(f"{'='*60}")
        print(f"\n{analysis}")

    sys.exit(0 if verdict == "benign" else 1 if verdict == "malicious" else 2)


if __name__ == "__main__":
    main()
