from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

logger = logging.getLogger("analysis.chain_tracker")

DECISION_PRIORITY: dict[str, int] = {"BLOCK": 3, "ALERT": 2, "LOG": 1, "PASS": 0}
ESCALATION: dict[str, str] = {"LOG": "ALERT", "ALERT": "BLOCK", "BLOCK": "BLOCK"}
COMBINATION_SEVERITY: dict[str, str] = {
    "USE": "CRITICAL",
    "SE": "HIGH",
    "US": "MEDIUM",
    "UE": "MEDIUM",
}


@dataclass
class ToolSequenceEntry:
    tool: str
    labels: list[str]
    timestamp: datetime
    event_id: int
    backend: str


@dataclass
class ChainTrackingResult:
    decision: Literal["PASS", "LOG", "ALERT", "BLOCK"]
    matched_combination: str | None
    step: str | None
    session_state: str
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "matched_combination": self.matched_combination,
            "step": self.step,
            "session_state": self.session_state,
            "context": self.context,
        }


class ChainTracker:
    def __init__(self, config: Any, toxic_flow_result_path: str) -> None:
        self._config = config
        self._auto_label_map: dict[str, list[str]] = {}
        self._label_map: dict[str, list[str]] = {}
        self._overridden: set[str] = set()
        self._dangerous_paths: list[dict[str, Any]] = []
        self._enabled: bool = config.enabled
        self._load_toxic_flow(toxic_flow_result_path)
        self._load_overrides()

    # ------------------------------------------------------------------
    # Startup
    # ------------------------------------------------------------------

    def _load_toxic_flow(self, path: str) -> None:
        if not os.path.exists(path):
            logger.warning(
                "Chain tracking disabled — toxic_flow_result.json not found at %s", path
            )
            self._enabled = False
            return
        try:
            with open(path) as f:
                data = json.load(f)
            tools: dict[str, Any] = data.get("tools", {})
            for tool_name, tool_data in tools.items():
                labels: list[str] = tool_data.get("labels", [])
                if labels:
                    self._auto_label_map[tool_name] = labels
            self._label_map = dict(self._auto_label_map)
            self._dangerous_paths = data.get("dangerous_paths", [])
            logger.info(
                "ChainTracker loaded label_map for %d tools, %d dangerous paths",
                len(self._label_map),
                len(self._dangerous_paths),
            )
        except Exception as exc:
            logger.error("ChainTracker failed to load toxic_flow result: %s", exc)
            self._enabled = False

    def _load_overrides(self) -> None:
        """Human-corrected labels persist across toxic-flow re-runs (rescan /
        add-backend / remove-backend all reconstruct ChainTracker from
        scratch) — re-apply them on top of the freshly computed auto labels."""
        try:
            from ..storage.repository import EventRepository  # noqa: PLC0415

            overrides = EventRepository().get_label_overrides()
        except Exception as exc:
            logger.error("ChainTracker failed to load label overrides: %s", exc)
            return
        for tool_name, labels in overrides.items():
            self._label_map[tool_name] = labels
            self._overridden.add(tool_name)
        if overrides:
            logger.info("ChainTracker applied %d label override(s).", len(overrides))

    def get_labels(self, tool_name: str) -> list[str]:
        return self._label_map.get(tool_name, [])

    def get_auto_labels(self, tool_name: str) -> list[str]:
        return self._auto_label_map.get(tool_name, [])

    def is_overridden(self, tool_name: str) -> bool:
        return tool_name in self._overridden

    def set_override(self, tool_name: str, labels: list[str]) -> None:
        from ..storage.repository import EventRepository  # noqa: PLC0415

        EventRepository().set_label_override(tool_name, labels)
        self._label_map[tool_name] = labels
        self._overridden.add(tool_name)

    def clear_override(self, tool_name: str) -> None:
        from ..storage.repository import EventRepository  # noqa: PLC0415

        EventRepository().delete_label_override(tool_name)
        self._label_map[tool_name] = list(self._auto_label_map.get(tool_name, []))
        self._overridden.discard(tool_name)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def check(
        self,
        session: Any,
        tool_name: str,
        event_id: int,
        backend: str,
    ) -> ChainTrackingResult:
        if not self._enabled:
            return ChainTrackingResult(
                decision="PASS",
                matched_combination=None,
                step=None,
                session_state=session.state.value,
            )

        # Append current call to tool_sequence
        entry = ToolSequenceEntry(
            tool=tool_name,
            labels=self.get_labels(tool_name),
            timestamp=datetime.now(tz=timezone.utc),
            event_id=event_id,
            backend=backend,
        )
        session.tool_sequence.append(entry)

        window = self._get_window(session)
        combinations = self._compute_combinations(window)

        if not combinations:
            return ChainTrackingResult(
                decision="PASS",
                matched_combination=None,
                step=None,
                session_state=session.state.value,
            )

        # Pick highest-priority decision across all active combinations
        best_decision = "PASS"
        best_combo: str | None = None
        best_step: str | None = None
        best_context: dict[str, Any] = {}

        for combo, info in combinations.items():
            decision = self._apply_policy(combo, info["step"], session.state.value)
            if DECISION_PRIORITY.get(decision, 0) > DECISION_PRIORITY.get(best_decision, 0):
                best_decision = decision
                best_combo = combo
                best_step = info["step"]
                best_context = self._build_context(combo, info, session.state.value)

        return ChainTrackingResult(
            decision=best_decision,  # type: ignore[arg-type]
            matched_combination=best_combo,
            step=best_step,
            session_state=session.state.value,
            context=best_context,
        )

    # ------------------------------------------------------------------
    # Window
    # ------------------------------------------------------------------

    def _get_window(self, session: Any) -> list[ToolSequenceEntry]:
        size = self._config.normal_window_size
        return session.tool_sequence[-size:]

    # ------------------------------------------------------------------
    # State machine (stateless, recomputed from window)
    # ------------------------------------------------------------------

    def _compute_combinations(
        self, window: list[ToolSequenceEntry]
    ) -> dict[str, dict[str, Any]]:
        """
        Scan window left-to-right and return all active chain combinations
        with their current step and the entries that triggered them.
        """
        u_seen = False
        u_entry: ToolSequenceEntry | None = None

        s_seen = False
        se_s_entry: ToolSequenceEntry | None = None

        us_seen = False
        us_s_entry: ToolSequenceEntry | None = None

        ue_seen = False
        ue_e_entry: ToolSequenceEntry | None = None

        se_seen = False
        se_e_entry: ToolSequenceEntry | None = None

        use_complete = False
        use_e_entry: ToolSequenceEntry | None = None

        for entry in window:
            for label in entry.labels:
                if label == "U":
                    if not u_seen:
                        u_seen = True
                        u_entry = entry

                elif label == "S":
                    if not s_seen:
                        s_seen = True
                        se_s_entry = entry
                    if u_seen and not us_seen:
                        us_seen = True
                        us_s_entry = entry

                elif label == "E":
                    if s_seen and not se_seen:
                        se_seen = True
                        se_e_entry = entry
                    if us_seen and not use_complete:
                        use_complete = True
                        use_e_entry = entry
                    if u_seen and not s_seen and not ue_seen:
                        ue_seen = True
                        ue_e_entry = entry

        results: dict[str, dict[str, Any]] = {}

        # USE chain (highest priority)
        if use_complete:
            results["USE"] = {
                "step": "3/3",
                "u_entry": u_entry,
                "s_entry": us_s_entry,
                "e_entry": use_e_entry,
            }
        elif us_seen:
            results["USE"] = {
                "step": "2/3",
                "u_entry": u_entry,
                "s_entry": us_s_entry,
                "e_entry": None,
            }
        elif u_seen:
            results["USE"] = {
                "step": "1/3",
                "u_entry": u_entry,
                "s_entry": None,
                "e_entry": None,
            }

        # SE chain
        if se_seen:
            results["SE"] = {
                "step": "2/2",
                "u_entry": None,
                "s_entry": se_s_entry,
                "e_entry": se_e_entry,
            }
        elif s_seen and not us_seen:
            # Only report partial SE if S is not already consumed by US
            results["SE"] = {
                "step": "1/2",
                "u_entry": None,
                "s_entry": se_s_entry,
                "e_entry": None,
            }

        # US chain (complete, not yet USE)
        if us_seen and not use_complete:
            results["US"] = {
                "step": "2/2",
                "u_entry": u_entry,
                "s_entry": us_s_entry,
                "e_entry": None,
            }

        # UE chain (complete)
        if ue_seen:
            results["UE"] = {
                "step": "2/2",
                "u_entry": u_entry,
                "s_entry": None,
                "e_entry": ue_e_entry,
            }

        return results

    # ------------------------------------------------------------------
    # Policy
    # ------------------------------------------------------------------

    def _apply_policy(self, combination: str, step: str, session_state: str) -> str:
        policies = self._config.policies
        policy = getattr(policies, combination, None)

        if policy is None:
            base: str = self._config.default_policy.upper()
        elif combination == "USE":
            if step == "1/3":
                base = policy.on_u_seen.upper()
            elif step == "2/3":
                base = policy.on_us_seen.upper()
            else:  # 3/3
                base = policy.on_complete.upper()
        else:  # SE, US, UE
            if step.startswith("1/"):
                base = policy.on_first.upper()
            else:
                base = policy.on_complete.upper()

        return base

    # ------------------------------------------------------------------
    # Context enrichment
    # ------------------------------------------------------------------

    def _build_context(
        self, combination: str, info: dict[str, Any], session_state: str
    ) -> dict[str, Any]:
        def _entry_dict(e: ToolSequenceEntry | None) -> dict[str, Any] | None:
            if e is None:
                return None
            return {
                "name": e.tool,
                "labels": e.labels,
                "event_id": e.event_id,
                "backend": e.backend,
            }

        ctx: dict[str, Any] = {
            "u_tool": _entry_dict(info.get("u_entry")),
            "s_tool": _entry_dict(info.get("s_entry")),
            "e_tool": _entry_dict(info.get("e_entry")),
            "session_state": session_state,
            "window_size": self._config.normal_window_size,
            "toxic_flow_path": None,
            "toxic_flow_severity": None,
            "toxic_flow_recommendation": None,
        }

        # Try to match against known Toxic Flow dangerous paths for enrichment
        u_tool = info.get("u_entry")
        s_tool = info.get("s_entry")
        e_tool = info.get("e_entry")

        for path in self._dangerous_paths:
            path_tools: list[str] = path.get("chain", [])
            if not path_tools:
                continue
            active_tools = {
                t.tool
                for t in [u_tool, s_tool, e_tool]
                if t is not None
            }
            if active_tools and active_tools.issubset(set(path_tools)):
                ctx["toxic_flow_path"] = path.get("id")
                ctx["toxic_flow_severity"] = path.get("severity")
                ctx["toxic_flow_recommendation"] = path.get("recommendation")
                break

        return ctx

    # ------------------------------------------------------------------
    # API helper
    # ------------------------------------------------------------------

    def get_chain_state(self, session: Any) -> dict[str, Any]:
        """Returns chain-state payload for GET /api/sessions/{id}/chain-state."""
        window = self._get_window(session)
        combinations = self._compute_combinations(window)

        # Derive a single human-readable state label
        if "USE" in combinations:
            step = combinations["USE"]["step"]
            current_state = (
                "USE_COMPLETE" if step == "3/3" else "US_SEEN" if step == "2/3" else "U_SEEN"
            )
        elif "SE" in combinations and combinations["SE"]["step"] == "2/2":
            current_state = "SE_SEEN"
        elif "US" in combinations:
            current_state = "US_SEEN"
        elif "UE" in combinations:
            current_state = "UE_SEEN"
        elif any(c in combinations for c in ("SE",)):
            current_state = "S_SEEN"
        else:
            current_state = "IDLE"

        active_combinations = [
            {
                "combination": combo,
                "step": info["step"],
                "severity": COMBINATION_SEVERITY.get(combo, "LOW"),
            }
            for combo, info in combinations.items()
        ]

        return {
            "session_id": session.session_id,
            "session_state": session.state.value,
            "last_transition_reason": getattr(session, "last_transition_reason", None),
            "state_changed_at": (
                session.state_changed_at.isoformat()
                if getattr(session, "state_changed_at", None) is not None
                else None
            ),
            "current_chain_state": current_state,
            "window_size": self._config.normal_window_size,
            "window_entries": [
                {
                    "tool": e.tool,
                    "labels": e.labels,
                    "backend": e.backend,
                    "timestamp": e.timestamp.isoformat(),
                }
                for e in window
            ],
            "active_combinations": active_combinations,
            "data_flow_tracking": self._config.data_flow_tracking,
            "alert_timeout_minutes": self._config.alert_timeout_minutes,
        }


def reconstruct_chain_state(
    tracker: ChainTracker,
    *,
    session_id: str,
    session_state: str,
    events: list[dict[str, Any]],
    routing_table: dict[str, str] | None = None,
    state_changed_at: str | None = None,
    last_transition_reason: str | None = None,
) -> dict[str, Any]:
    from ..proxy.session import SessionState  # noqa: PLC0415

    @dataclass
    class PersistedSessionView:
        session_id: str
        state: SessionState
        state_changed_at: datetime | None
        last_transition_reason: str | None
        tool_sequence: list[ToolSequenceEntry]

    tool_sequence: list[ToolSequenceEntry] = []
    for index, event in enumerate(events, start=1):
        if event.get("direction") != "request":
            continue
        tool_name = event.get("tool_name", "")
        timestamp = event.get("timestamp")
        backend_name = (routing_table or {}).get(tool_name, "persisted")
        tool_sequence.append(
            ToolSequenceEntry(
                tool=tool_name,
                labels=tracker.get_labels(tool_name),
                timestamp=datetime.fromisoformat(timestamp),
                event_id=index,
                backend=backend_name,
            )
        )

    try:
        normalized_state = SessionState(session_state)
    except ValueError:
        normalized_state = SessionState.NORMAL

    session = PersistedSessionView(
        session_id=session_id,
        state=normalized_state,
        state_changed_at=datetime.fromisoformat(state_changed_at) if state_changed_at else None,
        last_transition_reason=last_transition_reason,
        tool_sequence=tool_sequence,
    )
    return tracker.get_chain_state(session)
