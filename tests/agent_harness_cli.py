"""Agent-in-the-loop test driver using the `claude` CLI itself as the agent.

Unlike tests/agent_harness.py (which drives the tool-use loop by hand against
the Anthropic Messages API and needs ANTHROPIC_API_KEY), this module hands the
whole scenario to a single `claude -p` invocation and lets Claude Code run its
own internal agent loop against an MCP server we point it at. Authentication
comes from the CLI's own login (`claude` -> subscription OAuth), not an API key.

Caveat: with this approach we don't control the pacing of individual tool
calls (Claude Code drives the whole conversation internally), so in
"protected" mode there's a small race window where the model's first tool
call could land before MCPSec's startup toxic-flow discovery has finished
writing toxic_flow_result.json. tests/agent_harness.py avoids this by waiting
*before* issuing any tool call; here we can only wait *after* the run and
report what actually got recorded.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.agent_types import (  # noqa: E402
    AgentRunResult,
    Mode,
    ToolCallRecord,
    find_scenario,
    oracle_verdict,
)
from tests.harness import (  # noqa: E402
    DEMO_CONFIG,
    LOG_FILE,
    PYTHON,
    read_events,
    read_latest_session,
    reset_runtime_state,
    wait_for_analysis,
)

__all__ = ["find_scenario", "run_agent_scenario_cli"]


def _find_claude_bin() -> str:
    # CLAUDE_CLI_BIN env var wins (explicit override), then PATH lookup, then
    # the default `npm install -g` / native-installer location — some shells
    # (including this harness's subprocess environment) don't inherit the
    # PATH entry that an interactive login shell picks up.
    override = os.environ.get("CLAUDE_CLI_BIN")
    if override:
        return override
    found = shutil.which("claude")
    if found:
        return found
    fallback = Path.home() / ".local" / "bin" / "claude"
    return str(fallback)


CLAUDE_BIN = _find_claude_bin()
DEFAULT_MODEL = "sonnet"
RUN_TIMEOUT_SECONDS = 240


def _mcp_config(mode: Mode) -> dict[str, Any]:
    if mode == "baseline":
        args = [str(ROOT / "tests" / "mock_mcp_server.py")]
    else:
        args = [
            "-m",
            "mcpsec",
            "--config",
            str(DEMO_CONFIG),
            "--no-api",
            "--log-file",
            str(LOG_FILE),
        ]
    return {"mcpServers": {"mcpsec-test": {"command": str(PYTHON), "args": args}}}


def _parse_stream_json(stdout: str, result: AgentRunResult) -> None:
    pending_tool_uses: dict[str, dict[str, Any]] = {}

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        event_type = event.get("type")

        if event_type == "assistant":
            content = event.get("message", {}).get("content", [])
            text_parts = [b.get("text", "") for b in content if b.get("type") == "text"]
            tool_calls = []
            for block in content:
                if block.get("type") != "tool_use":
                    continue
                pending_tool_uses[block.get("id", "")] = {
                    "name": block.get("name", ""),
                    "input": block.get("input", {}),
                }
                tool_calls.append({"name": block.get("name", ""), "input": block.get("input", {})})
            if text_parts or tool_calls:
                result.transcript.append(
                    {
                        "role": "assistant",
                        "text": "\n".join(t for t in text_parts if t),
                        "tool_calls": tool_calls,
                    }
                )

        elif event_type == "user":
            content = event.get("message", {}).get("content", [])
            for block in content:
                if block.get("type") != "tool_result":
                    continue
                tool_use_id = block.get("tool_use_id", "")
                info = pending_tool_uses.get(tool_use_id, {})
                is_error = bool(block.get("is_error", False))
                raw_content = block.get("content", "")
                if isinstance(raw_content, list):
                    text = "\n".join(
                        c.get("text", "")
                        for c in raw_content
                        if isinstance(c, dict) and c.get("type") == "text"
                    )
                else:
                    text = str(raw_content)
                record = ToolCallRecord(
                    tool=info.get("name", "?"),
                    arguments=info.get("input", {}),
                    is_error=is_error,
                    result_text=text,
                )
                result.tool_calls.append(record)
                result.transcript.append(
                    {"role": "tool_result", "tool": record.tool, "is_error": is_error, "text": text}
                )

        elif event_type == "result":
            result.transcript.append({"role": "final", "text": event.get("result", ""), "raw": event})

        else:
            # Unrecognized event shape — kept raw so we can adjust the parser
            # once we see real `claude -p --output-format stream-json` output.
            result.transcript.append({"role": f"raw:{event_type}", "text": line[:500]})


def run_agent_scenario_cli(scenario: dict[str, Any], mode: Mode) -> AgentRunResult:
    if mode == "protected":
        reset_runtime_state()

    model = scenario.get("model", DEFAULT_MODEL)
    system_prompt = scenario.get("system_prompt", "You are a helpful assistant.")
    user_prompt = scenario["user_prompt"]

    result = AgentRunResult(mode=mode)

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, dir=str(ROOT)) as f:
        json.dump(_mcp_config(mode), f)
        mcp_config_path = Path(f.name)

    command = [
        CLAUDE_BIN,
        "-p",
        user_prompt,
        "--system-prompt",
        system_prompt,
        "--mcp-config",
        str(mcp_config_path),
        "--strict-mcp-config",
        "--tools",
        "",
        "--dangerously-skip-permissions",
        "--no-session-persistence",
        "--output-format",
        "stream-json",
        "--verbose",
        "--model",
        model,
    ]

    try:
        proc = subprocess.run(
            command, cwd=str(ROOT), capture_output=True, text=True, timeout=RUN_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired:
        result.transcript.append(
            {"role": "error", "text": f"claude did not finish within {RUN_TIMEOUT_SECONDS}s"}
        )
        return result
    finally:
        mcp_config_path.unlink(missing_ok=True)

    if proc.returncode != 0:
        result.transcript.append(
            {"role": "error", "text": f"claude exited {proc.returncode}: {proc.stderr[-2000:]}"}
        )
        return result

    _parse_stream_json(proc.stdout, result)

    if mode == "protected":
        wait_for_analysis()
        result.session = read_latest_session()
        result.events = read_events(result.session["session_id"])

    result.oracle = oracle_verdict(result.tool_calls, scenario.get("oracle", {}))
    return result
