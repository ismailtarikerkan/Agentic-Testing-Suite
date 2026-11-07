"""Agent-in-the-loop test driver for a model served by OpenRouter, over real MCP.

Same shape as tests/agent_harness_ollama.py — real MCP (initialize ->
tools/list -> tools/call) against either the mock backend directly
("baseline") or through the MCPSec proxy ("protected") — but the "brain" is
a hosted model reached through OpenRouter's OpenAI-compatible
/chat/completions endpoint instead of a local Ollama model. The main
difference from the Ollama engine: OpenAI-style tool_calls carry their
arguments as a JSON *string*, not a dict, and tool results are threaded back
with a `tool_call_id` rather than Ollama's bare `name` field.

Needs OPENROUTER_API_KEY in the environment.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

load_dotenv(ROOT / ".env")

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

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "qwen/qwen3.6-35b-a3b"
DEFAULT_MAX_TURNS = 8

__all__ = ["find_scenario", "run_agent_scenario_openrouter"]


def mcp_tools_to_openai(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not set.")
    response = httpx.post(
        OPENROUTER_URL,
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "model": model,
            "messages": messages,
            "tools": tools,
            "temperature": 0,
        },
        timeout=300,
    )
    response.raise_for_status()
    body = response.json()
    if "error" in body:
        raise RuntimeError(f"OpenRouter error: {body['error']}")
    return body["choices"][0]["message"]


def run_agent_scenario_openrouter(scenario: dict[str, Any], mode: Mode) -> AgentRunResult:
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
            "clientInfo": {"name": "agent-harness-openrouter", "version": "0.1.0"},
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
        openai_tools = mcp_tools_to_openai(mcp_tools)

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": scenario["user_prompt"]},
        ]

        for _turn in range(max_turns):
            message = chat(messages, model, openai_tools)
            messages.append(message)

            tool_calls = message.get("tool_calls") or []
            result.transcript.append(
                {
                    "role": "assistant",
                    "text": message.get("content") or "",
                    "tool_calls": [
                        {
                            "name": tc["function"]["name"],
                            "input": _tool_call_args(tc["function"].get("arguments")),
                        }
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
                messages.append(
                    {"role": "tool", "tool_call_id": tc["id"], "content": text}
                )
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
