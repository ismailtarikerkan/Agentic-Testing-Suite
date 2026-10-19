from __future__ import annotations

import os
from typing import Any

import yaml
from fastapi import APIRouter, HTTPException

from ..state import state
from ...storage.repository import EventRepository

router = APIRouter(prefix="/api/backends")

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "mcpsec-config.yaml")


def _save_config() -> None:
    if state.config is None:
        return
    # Write back to whichever config file the proxy was actually started
    # with (--config), not a hardcoded default — otherwise saving while
    # running with e.g. mcpsec-demo-config.yaml silently overwrites the
    # real mcpsec-config.yaml.
    path = state.config_path or os.path.abspath(_CONFIG_PATH)
    with open(path, "w") as f:
        yaml.dump(state.config.model_dump(), f, default_flow_style=False)


@router.get("")
async def list_backends() -> list[dict[str, Any]]:
    if state.config is None:
        return []
    result = []
    for backend in state.config.backends:
        entry = backend.model_dump()
        # Determine running status from proxy transport if available
        running = False
        if state.proxy is not None and state.proxy._transport is not None:
            running = backend.name in state.proxy._transport.running_backends()
        entry["status"] = "running" if running else "stopped"
        result.append(entry)
    return result


@router.post("")
async def add_backend(backend_data: dict[str, Any]) -> dict[str, Any]:
    if state.config is None:
        raise HTTPException(status_code=503, detail="Config not loaded.")
    from ...config import BackendConfig  # noqa: PLC0415

    try:
        new_backend = BackendConfig.model_validate(backend_data)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if any(b.name == new_backend.name for b in state.config.backends):
        raise HTTPException(status_code=409, detail=f"Backend '{new_backend.name}' already exists.")

    state.config.backends.append(new_backend)
    _save_config()

    result = new_backend.model_dump()
    if state.proxy is not None and state.proxy.is_running:
        try:
            live_summary = await state.proxy.add_backend_live(new_backend)
            result["live"] = True
            result["discovery"] = live_summary
        except Exception as exc:
            result["live"] = False
            result["live_error"] = str(exc)
    else:
        result["live"] = False
        result["live_error"] = "Proxy not running — saved to config, will start on next launch."
    return result


@router.put("/{name}")
async def update_backend(name: str, update: dict[str, Any]) -> dict[str, Any]:
    if state.config is None:
        raise HTTPException(status_code=503, detail="Config not loaded.")

    for i, backend in enumerate(state.config.backends):
        if backend.name == name:
            merged = backend.model_dump()
            merged.update(update)
            from ...config import BackendConfig  # noqa: PLC0415

            try:
                state.config.backends[i] = BackendConfig.model_validate(merged)
            except Exception as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            _save_config()
            return state.config.backends[i].model_dump()

    raise HTTPException(status_code=404, detail=f"Backend '{name}' not found.")


@router.delete("/{name}")
async def delete_backend(name: str) -> dict[str, Any]:
    if state.config is None:
        raise HTTPException(status_code=503, detail="Config not loaded.")

    for i, backend in enumerate(state.config.backends):
        if backend.name == name:
            state.config.backends.pop(i)
            _save_config()
            return {"deleted": name}

    raise HTTPException(status_code=404, detail=f"Backend '{name}' not found.")


@router.post("/reset-runtime")
async def reset_runtime_state() -> dict[str, Any]:
    repo = EventRepository()
    result = repo.clear_runtime_state()
    return {
        "status": "ok",
        **result,
    }
