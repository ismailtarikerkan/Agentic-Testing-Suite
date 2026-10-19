from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys


def _setup_logging(level: str = "INFO", log_file: str | None = None) -> None:
    fmt = "%(asctime)s [%(levelname)-8s] %(name)-20s %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(numeric_level)
    formatter = logging.Formatter(fmt, datefmt=datefmt)
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(formatter)
        root.addHandler(fh)
    else:
        # stderr handler (captured/swallowed when spawned by Claude Code)
        sh = logging.StreamHandler()
        sh.setFormatter(formatter)
        root.addHandler(sh)


def main() -> None:
    parser = argparse.ArgumentParser(description="MCPSec — MCP Security Proxy")
    parser.add_argument(
        "--config",
        default="mcpsec-config.yaml",
        help="Path to mcpsec-config.yaml (default: mcpsec-config.yaml)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level (default: INFO)",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Write logs to this file instead of stderr (required when spawned by Claude Code)",
    )
    parser.add_argument(
        "--no-api",
        action="store_true",
        help="Disable REST API server (use when spawned as subprocess alongside a standalone instance)",
    )
    parser.add_argument(
        "--no-backends",
        action="store_true",
        help="Do not spawn backend MCP processes (use for standalone API-only mode)",
    )
    parser.add_argument(
        "--standalone",
        action="store_true",
        help="Run as a persistent service (no MCP client required): spawns backends, "
             "auto-initializes them, builds routing table, runs discovery, then serves the API",
    )
    parser.add_argument(
        "--sse",
        action="store_true",
        help="Enable MCP HTTP+SSE transport: like --standalone but also accepts MCP client "
             "connections at GET /sse and POST /messages. Configure MCP clients with "
             "type=sse, url=http://localhost:<api_port>/sse instead of spawning via stdio.",
    )
    args = parser.parse_args()

    _setup_logging(args.log_level, args.log_file)
    logger = logging.getLogger("main")

    # Load config
    from .config import load_config  # noqa: PLC0415

    try:
        config = load_config(args.config)
    except FileNotFoundError:
        print(f"ERROR: Config file not found: {args.config}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: Invalid config: {exc}", file=sys.stderr)
        sys.exit(1)

    logger.info("MCPSec starting... (transport=%s, no_backends=%s)", config.proxy.transport, args.no_backends)

    from .proxy.core import ProxyCore  # noqa: PLC0415

    core = ProxyCore(config, no_backends=args.no_backends, standalone=args.standalone, sse=args.sse)

    # Populate shared API state
    from .api import state as api_state  # noqa: PLC0415

    api_state.state.proxy = core
    api_state.state.router = core.router
    api_state.state.sessions = core.session_manager
    api_state.state.config = config
    api_state.state.config_path = os.path.abspath(args.config)
    # chain_tracker and toxic_flow are set on core after discovery runs;
    # state references core directly so they're accessible via state.proxy.chain_tracker

    async def _run() -> None:
        import signal

        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(_shutdown()))

        tasks: list[asyncio.Task] = []  # type: ignore[type-arg]
        api_server = None  # uvicorn.Server, set below if API is enabled

        if config.api.enabled and not args.no_api:
            from .api.server import create_app, make_api_server  # noqa: PLC0415

            app = create_app()

            if args.sse:
                # Register MCP HTTP+SSE endpoints on the same FastAPI app
                from .proxy.sse_transport import create_mcp_sse_router  # noqa: PLC0415
                app.include_router(create_mcp_sse_router(core))
                logger.info(
                    "MCP SSE transport enabled: GET http://0.0.0.0:%d/sse  "
                    "POST http://0.0.0.0:%d/messages",
                    config.api.port, config.api.port,
                )

            api_server = make_api_server(app, host="0.0.0.0", port=config.api.port)
            api_task = asyncio.create_task(api_server.serve())
            tasks.append(api_task)

        async def _shutdown() -> None:
            await core.stop()
            # Graceful uvicorn shutdown — avoids CancelledError lifespan trace.
            if api_server is not None:
                api_server.should_exit = True
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        try:
            await core.start()
        except KeyboardInterrupt:
            pass
        finally:
            await _shutdown()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        logger.info("MCPSec stopped by user.")


if __name__ == "__main__":
    main()
