"""Agent-in-the-loop test driver for a local Ollama model, over real MCP.

Like tests/agent_harness.py, but the "brain" is a local model served by
Ollama instead of the Anthropic API. The model talks real MCP (initialize ->
tools/list -> tools/call) to either the mock backend directly ("baseline")
or through the MCPSec proxy ("protected"), using Ollama's native tool-calling
support (the `tools` field on /api/chat).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.agent_harness import _extract_mcp_text, _spawn_backend  # noqa: E402
from tests.agent_types import (  # noqa: E402
    AgentRunResult,
    Mode,
    ToolCallRecord,
    find_scenario,
    oracle_verdict,
)
from tests.harness import (  # noqa: E402
    _send_message,
    _send_notification,
    read_events,
    read_latest_session,
    reset_runtime_state,
    wait_for_analysis,
)

OLLAMA_URL = "http://localhost:11434/api/chat"
DEFAULT_MODEL = "qwen2.5:7b"
DEFAULT_MAX_TURNS = 8

__all__ = ["find_scenario", "run_agent_scenario_ollama"]


def mcp_tools_to_ollama(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "parameters": tool.get("inputSchema", {"type": "object", "properties": {}}),
            },
        }
        for tool in tools
    ]


def _tool_call_args(raw: Any) -> dict[str, Any]:
    """Ollama returns tool_call arguments as a dict already; be lenient
    in case a model/version serializes them as a JSON string instead."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {"_raw": raw}
        return parsed if isinstance(parsed, dict) else {"_raw": parsed}
    return {}


def chat(messages: list[dict[str, Any]], model: str, tools: list[dict[str, Any]]) -> dict[str, Any]:
    response = httpx.post(
        OLLAMA_URL,
        json={
            "model": model,
            "messages": messages,
            "tools": tools,
            "stream": False,
            "options": {"temperature": 0},
        },
        timeout=300,
    )
    response.raise_for_status()
    return response.json()["message"]


def run_agent_scenario_ollama(scenario: dict[str, Any], mode: Mode) -> AgentRunResult:
    if mode == "protected":
        reset_runtime_state()

    model = scenario.get("model", DEFAULT_MODEL)
    max_turns = scenario.get("max_turns", DEFAULT_MAX_TURNS)
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
            "clientInfo": {"name": "agent-harness-ollama", "version": "0.1.0"},
        })
        _send_notification(
            process, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
        )
        tools_response = send("tools/list", {})
        if mode == "protected":
            wait_for_analysis()
        mcp_tools = tools_response.get("result", {}).get("tools", [])
        exclude_tools = set(scenario.get("exclude_tools", []))
        if exclude_tools:
            mcp_tools = [t for t in mcp_tools if t["name"] not in exclude_tools]
        ollama_tools = mcp_tools_to_ollama(mcp_tools)

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": scenario["user_prompt"]},
        ]

        for _turn in range(max_turns):
            message = chat(messages, model, ollama_tools)
            messages.append(message)

            tool_calls = message.get("tool_calls") or []
            result.transcript.append(
                {
                    "role": "assistant",
                    "text": message.get("content", ""),
                    "tool_calls": [
                        {"name": tc["function"]["name"], "input": _tool_call_args(tc["function"].get("arguments"))}
                        for tc in tool_calls
                    ],
                }
            )

            if not tool_calls:
                break

            for tc in tool_calls:
                name = tc["function"]["name"]
                arguments = _tool_call_args(tc["function"].get("arguments"))
                mcp_response = send("tools/call", {"name": name, "arguments": arguments})
                text, is_error = _extract_mcp_text(mcp_response)
                record = ToolCallRecord(
                    tool=name, arguments=arguments, is_error=is_error, result_text=text
                )
                result.tool_calls.append(record)
                result.transcript.append(
                    {
                        "role": "tool_result",
                        "tool": name,
                        "is_error": is_error,
                        "text": text,
                    }
                )
                messages.append({"role": "tool", "content": text, "name": name})
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
