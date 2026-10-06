"""Agent-in-the-loop test driver.

Unlike tests/harness.py (which replays a fixed list of tool calls), this
module lets a real Claude model decide which tools to call, in response to
tool results it receives — including an injection payload from the mock
backend. The same tool implementations (tests/mock_mcp_server.py) are used
in both modes so the comparison is apples-to-apples:

- "baseline": the agent talks directly to the mock backend (no MCPSec).
- "protected": the agent talks to the mock backend through the MCPSec proxy.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

import anthropic

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
    _send_message,
    _send_notification,
    read_events,
    read_latest_session,
    reset_runtime_state,
    wait_for_analysis,
)

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_MAX_TOKENS = 1024

__all__ = ["find_scenario", "run_agent_scenario"]


def mcp_tools_to_anthropic(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": tool["name"],
            "description": tool.get("description", ""),
            "input_schema": tool.get("inputSchema", {"type": "object", "properties": {}}),
        }
        for tool in tools
    ]


def _extract_mcp_text(mcp_response: dict[str, Any]) -> tuple[str, bool]:
    error = mcp_response.get("error")
    if error is not None:
        return error.get("message", str(error)), True
    result = mcp_response.get("result") or {}
    chunks = result.get("content", [])
    text = "\n".join(c.get("text", "") for c in chunks if c.get("type") == "text")
    return text, False


def _spawn_backend(mode: Mode) -> subprocess.Popen[str]:
    if mode == "baseline":
        command = [str(PYTHON), str(ROOT / "tests" / "mock_mcp_server.py")]
    else:
        command = [
            str(PYTHON),
            "-m",
            "mcpsec",
            "--config",
            str(DEMO_CONFIG),
            "--no-api",
            "--log-file",
            str(LOG_FILE),
        ]
    return subprocess.Popen(
        command,
        cwd=str(ROOT),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def run_agent_scenario(scenario: dict[str, Any], mode: Mode) -> AgentRunResult:
    if mode == "protected":
        reset_runtime_state()

    client = anthropic.Anthropic()
    model = scenario.get("model", DEFAULT_MODEL)
    max_turns = scenario.get("max_turns", 8)
    system_prompt = scenario.get("system_prompt", "You are a helpful assistant.")

    result = AgentRunResult(mode=mode)
    process = _spawn_backend(mode)
    next_id = 1

    def send(method: str, params: dict[str, Any]) -> dict[str, Any]:
        nonlocal next_id
        next_id += 1
        return _send_message(
            process, {"jsonrpc": "2.0", "id": next_id, "method": method, "params": params}
        )

    try:
        send("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "agent-harness", "version": "0.1.0"},
        })
        _send_notification(
            process, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
        )
        tools_response = send("tools/list", {})
        if mode == "protected":
            wait_for_analysis()
        mcp_tools = tools_response.get("result", {}).get("tools", [])
        anthropic_tools = mcp_tools_to_anthropic(mcp_tools)

        messages: list[dict[str, Any]] = [
            {"role": "user", "content": scenario["user_prompt"]}
        ]

        for _turn in range(max_turns):
            response = client.messages.create(
                model=model,
                max_tokens=DEFAULT_MAX_TOKENS,
                system=system_prompt,
                messages=messages,
                tools=anthropic_tools,
            )
            messages.append({"role": "assistant", "content": response.content})

            tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
            text_blocks = [b.text for b in response.content if b.type == "text"]
            result.transcript.append(
                {
                    "role": "assistant",
                    "text": "\n".join(text_blocks),
                    "tool_calls": [{"name": b.name, "input": b.input} for b in tool_use_blocks],
                }
            )

            if not tool_use_blocks:
                break

            tool_result_content = []
            for block in tool_use_blocks:
                mcp_response = send(
                    "tools/call", {"name": block.name, "arguments": block.input}
                )
                text, is_error = _extract_mcp_text(mcp_response)
                record = ToolCallRecord(
                    tool=block.name, arguments=block.input, is_error=is_error, result_text=text
                )
                result.tool_calls.append(record)
                result.transcript.append(
                    {
                        "role": "tool_result",
                        "tool": block.name,
                        "is_error": is_error,
                        "text": text,
                    }
                )
                tool_result_content.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": text,
                        "is_error": is_error,
                    }
                )
            messages.append({"role": "user", "content": tool_result_content})
    finally:
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=3)

    if mode == "protected":
        result.session = read_latest_session()
        result.events = read_events(result.session["session_id"])

    result.oracle = oracle_verdict(result.tool_calls, scenario.get("oracle", {}))
    return result
