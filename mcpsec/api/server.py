from __future__ import annotations

import asyncio
import logging

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes import (
    analysis,
    anomaly_config,
    backends,
    config,
    events,
    features,
    overrides,
    proxy,
    rescan,
    routing,
    rules,
    scenarios,
    sessions,
    tool_changes,
)
from .websocket import router as ws_router

logger = logging.getLogger("api.server")


def create_app() -> FastAPI:
    app = FastAPI(title="MCPSec API", version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(events.router)
    app.include_router(sessions.router)
    app.include_router(routing.router)
    app.include_router(analysis.router)
    app.include_router(config.router)
    app.include_router(proxy.router)
    app.include_router(backends.router)
    app.include_router(overrides.router)
    app.include_router(rules.router)
    app.include_router(features.router)
    app.include_router(rescan.router)
    app.include_router(anomaly_config.router)
    app.include_router(scenarios.router)
    app.include_router(tool_changes.router)
    app.include_router(ws_router)

    return app


def make_api_server(app: FastAPI, host: str, port: int) -> uvicorn.Server:
    """Build the uvicorn Server.  Caller owns the lifecycle:
    `await server.serve()` to run, `server.should_exit = True` for graceful stop.
    Avoids the `asyncio.CancelledError` lifespan traceback that occurs when
    the serve task is cancelled directly.
    """
    config_obj = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
        loop="none",
    )
    server = uvicorn.Server(config_obj)
    logger.info("API server running at http://%s:%d", host, port)
    return server


async def start_api_server(app: FastAPI, host: str, port: int) -> None:
    """Backwards-compatible wrapper — prefer `make_api_server` for graceful shutdown."""
    server = make_api_server(app, host, port)
    await server.serve()
