from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from ..state import state

router = APIRouter(prefix="/api/overrides")

_VALID_LABELS = {"U", "S", "E"}


def _validate_labels(body: dict[str, Any]) -> list[str]:
    labels = body.get("labels")
    if not isinstance(labels, list) or not all(isinstance(l, str) and l in _VALID_LABELS for l in labels):
        raise HTTPException(status_code=422, detail="labels must be a list containing only 'U', 'S', 'E'.")
    return labels


@router.get("")
async def list_overrides() -> dict[str, list[str]]:
    from ...storage.repository import EventRepository  # noqa: PLC0415

    return EventRepository().get_label_overrides()


@router.put("/{tool_name}")
async def set_override(tool_name: str, body: dict[str, Any]) -> dict[str, Any]:
    labels = _validate_labels(body)
    if state.proxy is not None and state.proxy.chain_tracker is not None:
        state.proxy.chain_tracker.set_override(tool_name, labels)
    else:
        from ...storage.repository import EventRepository  # noqa: PLC0415

        EventRepository().set_label_override(tool_name, labels)
    return {"tool_name": tool_name, "labels": labels, "overridden": True}


@router.delete("/{tool_name}")
async def clear_override(tool_name: str) -> dict[str, Any]:
    if state.proxy is not None and state.proxy.chain_tracker is not None:
        state.proxy.chain_tracker.clear_override(tool_name)
        auto_labels = state.proxy.chain_tracker.get_labels(tool_name)
    else:
        from ...storage.repository import EventRepository  # noqa: PLC0415

        EventRepository().delete_label_override(tool_name)
        auto_labels = []
    return {"tool_name": tool_name, "labels": auto_labels, "overridden": False}
