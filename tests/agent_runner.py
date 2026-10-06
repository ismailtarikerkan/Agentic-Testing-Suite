#!/usr/bin/env python3

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.agent_types import AgentRunResult, find_scenario  # noqa: E402
from tests.harness import load_scenario  # noqa: E402

MODES = ("baseline", "protected")
ENGINES = ("cli", "api")


def _print_transcript(result: AgentRunResult) -> None:
    for entry in result.transcript:
        role = entry.get("role", "?")
        if role == "assistant":
            if entry.get("text"):
                print(f"  [assistant] {entry['text']}")
            for call in entry.get("tool_calls", []):
                print(f"  [tool_call] {call['name']}({call['input']})")
        elif role == "tool_result":
            marker = "ERROR" if entry.get("is_error") else "ok"
            print(f"  [tool_result:{marker}] {entry['tool']} -> {entry['text']}")
        elif role == "final":
            print(f"  [final] {entry.get('text', '')}")
        elif role == "error":
            print(f"  [error] {entry.get('text', '')}")
        else:
            print(f"  [{role}] {entry.get('text', '')}")


def _print_events(result: AgentRunResult) -> None:
    if not result.events:
        return
    print("  proxy events:")
    for event in result.events:
        print(
            f"    {event['direction']:8} tool={event['tool_name']:<20} "
            f"decision={event['decision']:<5} flags={','.join(event['flags']) or '-'}"
        )


def run_mode(scenario: dict, mode: str, engine: str) -> AgentRunResult:
    print(f"--- {scenario['id']} [{mode}] (engine={engine}) ---")
    if engine == "cli":
        from tests.agent_harness_cli import run_agent_scenario_cli as run

        result = run(scenario, mode)  # type: ignore[arg-type]
    else:
        from tests.agent_harness import run_agent_scenario as run

        result = run(scenario, mode)  # type: ignore[arg-type]
    _print_transcript(result)
    _print_events(result)
    print(f"  oracle: {result.oracle}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Run an agent-in-the-loop MCPSec scenario")
    parser.add_argument("scenario", help="Scenario id prefix, e.g. AGENT-001")
    parser.add_argument("--mode", choices=(*MODES, "both"), default="both")
    parser.add_argument(
        "--engine",
        choices=ENGINES,
        default="cli",
        help="cli: drive the `claude` CLI (no API key needed). "
        "api: call the Anthropic Messages API directly (needs ANTHROPIC_API_KEY).",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Override the scenario's `model` field (e.g. 'haiku', 'sonnet', "
        "'claude-haiku-4-5'). Useful for comparing attack success rate across model tiers.",
    )
    args = parser.parse_args()

    scenario_path = find_scenario(args.scenario)
    scenario = load_scenario(scenario_path)
    if args.model:
        scenario = {**scenario, "model": args.model}

    modes = MODES if args.mode == "both" else (args.mode,)
    for mode in modes:
        run_mode(scenario, mode, args.engine)


if __name__ == "__main__":
    main()
