from __future__ import annotations

from typing import Any

from fastapi import APIRouter

router = APIRouter(prefix="/api/tool-changes")


@router.get("")
async def list_tool_changes(limit: int = 100) -> list[dict[str, Any]]:
    from ...storage.repository import EventRepository  # noqa: PLC0415

    return EventRepository().get_tool_changes(limit=limit)
