from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import traceback
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

# Per-async-task context: which send_fn to use for the current message handler.
# Using ContextVar makes it safe for concurrent SSE clients (each asyncio Task
# gets its own copy of the context).
_current_send_fn: contextvars.ContextVar[
    Callable[[Any], Awaitable[None]] | None
] = contextvars.ContextVar("current_send_fn", default=None)

from ..analysis.regex_filter import analyze_request, analyze_response, redact_credentials
from ..config import BackendConfig, MCPSecConfig
from ..discovery.discovery import ToolDiscovery
from ..enforcement.engine import apply_tainted_escalation, decide, more_restrictive
from ..storage.repository import EventRepository
from .base import MCPMessage
from .router import Router, ToolNotFoundError
from .session import Session, SessionEvent, SessionManager
from .stdio_transport import StdioTransport

logger = logging.getLogger("proxy.core")


class ProxyCore:
    def __init__(self, config: MCPSecConfig, no_backends: bool = False, standalone: bool = False, sse: bool = False) -> None:
        self._config = config
        self._no_backends = no_backends
        self._standalone = standalone
        self._sse = sse
        self._session_manager = SessionManager()
        self._router = Router()
        self._transport: StdioTransport | None = None
        self._running = False
        self._current_session: Session | None = None
        self.discovery: ToolDiscovery | None = None
        self._discovery_started = False
        self._tools_cache: list[dict[str, Any]] | None = None
        self.toxic_flow: Any | None = None  # ToxicFlowAnalyzer, set after discovery
        self.chain_tracker: Any | None = None  # ChainTracker, set after toxic flow
        self.anomaly_detector: Any | None = None  # AnomalyDetector, initialized at startup
        self._repo = EventRepository()
        # SSE client registry: client_id -> send_fn coroutine
        self._sse_clients: dict[str, Callable[[Any], Awaitable[None]]] = {}

    # ------------------------------------------------------------------
    # SSE client management
    # ------------------------------------------------------------------

    def register_sse_client(self, client_id: str, send_fn: Callable[[Any], Awaitable[None]]) -> None:
        self._sse_clients[client_id] = send_fn

    def unregister_sse_client(self, client_id: str) -> None:
        self._sse_clients.pop(client_id, None)

    async def handle_sse_message(self, msg: "MCPMessage", client_id: str) -> None:
        """Process an incoming MCP message from an SSE client."""
        send_fn = self._sse_clients.get(client_id)
        if send_fn is None:
            logger.warning("handle_sse_message: unknown client_id=%s", client_id)
            return
        token = _current_send_fn.set(send_fn)
        try:
            await self._handle_message(msg)
        finally:
            _current_send_fn.reset(token)

    async def _send_to_client(self, msg: "MCPMessage") -> None:
        """Send a response to the current MCP client (stdio or SSE)."""
        fn = _current_send_fn.get()
        if fn is not None:
            await fn(msg)
        elif self._transport is not None:
            await self._transport.send_to_client(msg)

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def router(self) -> Router:
        return self._router

    @property
    def session_manager(self) -> SessionManager:
        return self._session_manager

    async def start(self) -> None:
        logger.info(
            "ProxyCore starting... (standalone=%s, sse=%s, no_backends=%s)",
            self._standalone, self._sse, self._no_backends,
        )
        backends = [] if self._no_backends else self._config.backends
        self._transport = StdioTransport(backends)
        await self._transport.start()

        self._running = True
        if (self._standalone or self._sse) and not self._no_backends:
            # Standalone / SSE mode: auto-initialize backends, build routing
            # table, run discovery, then keep alive waiting for API/SSE calls.
            await self._standalone_init()
            while self._running:
                await asyncio.sleep(1)
        elif not self._no_backends:
            # Classic stdio proxy mode: read MCP messages from stdin.
            await self._message_loop()
        else:
            # API-only mode: no message loop, just keep alive until stopped.
            while self._running:
                await asyncio.sleep(1)

    async def _standalone_init(self) -> None:
        """Auto-initialize all backends without a MCP client on stdin."""
        assert self._transport is not None
        backend_names = self._transport.running_backends()
        if not backend_names:
            logger.warning("Standalone mode: no backends running, skipping init.")
            return

        logger.info("Standalone mode: initializing %d backends...", len(backend_names))
        init_msg = MCPMessage(
            id=0,
            method="initialize",
            params={
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcpsec-standalone", "version": "0.1.0"},
            },
            raw={},
        )
        for name in backend_names:
            try:
                await self._transport.send_to_backend(name, init_msg)
                logger.debug("Backend '%s' initialized (standalone)", name)
            except Exception as exc:
                logger.warning("Failed to initialize backend '%s': %s", name, exc)

        initialized_notif = MCPMessage(method="notifications/initialized", params={}, raw={})
        for name in backend_names:
            try:
                await self._transport.send_notification_to_backend(name, initialized_notif)
            except Exception as exc:
                logger.warning("Failed to send notifications/initialized to '%s': %s", name, exc)

        # Build routing table
        try:
            self._tools_cache = await self._router.build(self._transport, backend_names)
            logger.info("Standalone: routing table built (%d tools)", len(self._tools_cache))
            self._repo.save_routing_table(self._router.get_routing_table())
        except Exception as exc:
            logger.error("Standalone: failed to build routing table: %s", exc)

        # Create a session for tracking
        session = self._session_manager.create_session()
        self._current_session = session
        self._repo.upsert_session(session.session_id, session.created_at.isoformat(), session.state.value, 0)

        # Run discovery + analysis pipeline
        self.discovery = ToolDiscovery(self._transport, backend_names, self._config)
        self._discovery_started = True
        await self._run_discovery()

    async def stop(self) -> None:
        logger.info("ProxyCore stopping...")
        self._running = False
        if self._transport:
            await self._transport.close()

    async def _run_discovery(self) -> None:
        discovery_result: dict = {}
        try:
            discovery_result = await self.discovery.run()
            logger.info(
                "Discovery complete: %d backends processed.",
                len(discovery_result.get("backends", {})),
            )
        except Exception as exc:
            logger.error("Tool discovery failed (non-fatal): %s", exc)

        # Toxic flow analysis — runs after discovery completes
        if discovery_result:
            try:
                from ..analysis.toxic_flow import ToxicFlowAnalyzer  # noqa: PLC0415
                self.toxic_flow = ToxicFlowAnalyzer(
                    self._config.toxic_flow,
                    self._config.toxic_flow.result_path,
                )
                tf_result = self.toxic_flow.run(discovery_result)
                logger.info(
                    "Toxic flow analysis complete. Session severity: %s",
                    tf_result["session_severity"],
                )
            except ImportError:
                logger.debug("ToxicFlowAnalyzer not yet available, skipping.")
            except Exception as exc:
                logger.error("Toxic flow analysis failed (non-fatal): %s", exc)

        # Chain tracking — runs after toxic flow (needs label map from result)
        if self._config.chain_tracking.enabled:
            try:
                from ..analysis.chain_tracker import ChainTracker  # noqa: PLC0415
                self.chain_tracker = ChainTracker(
                    self._config.chain_tracking,
                    self._config.chain_tracking.result_path,
                )
                logger.info("ChainTracker initialized.")
            except Exception as exc:
                logger.error("ChainTracker init failed (non-fatal): %s", exc)

        # Anomaly detection — predefined rules + adaptive EMA baseline,
        # severity fused with Toxic Flow labels (context-aware scoring)
        if self._config.anomaly_detection.enabled:
            try:
                from ..analysis.anomaly_detector import AnomalyDetector  # noqa: PLC0415
                tf_loader = None
                if self._config.anomaly_detection.toxic_flow_integration.enabled:
                    from ..analysis.toxic_flow import ToxicFlowLoader  # noqa: PLC0415
                    tf_loader = ToxicFlowLoader(self._config.toxic_flow.result_path)
                    tf_loader.load()
                self.anomaly_detector = AnomalyDetector(
                    self._config.anomaly_detection, tf_loader
                )
                logger.info(
                    "AnomalyDetector initialized (toxic-flow fusion: %s).",
                    "on" if tf_loader is not None else "off",
                )
            except Exception as exc:
                logger.error("AnomalyDetector init failed (non-fatal): %s", exc)

    # ------------------------------------------------------------------
    # Live backend registration (hot-add without restart)
    # ------------------------------------------------------------------

    async def add_backend_live(self, backend: BackendConfig) -> dict[str, Any]:
        """Spawn a new backend into the running proxy, re-run discovery/toxic-flow
        for the full (now-larger) backend set, and notify connected clients that
        the tool list changed. Raises ValueError on a name collision."""
        assert self._transport is not None

        if backend.name in self._transport.all_backend_names():
            raise ValueError(f"Backend '{backend.name}' already exists.")

        ok = await self._transport.add_backend(backend)
        if not ok:
            raise RuntimeError(f"Failed to spawn backend '{backend.name}'.")

        init_msg = MCPMessage(
            id=0,
            method="initialize",
            params={
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcpsec-live-add", "version": "0.1.0"},
            },
            raw={},
        )
        await self._transport.send_to_backend(backend.name, init_msg)
        await self._transport.send_notification_to_backend(
            backend.name, MCPMessage(method="notifications/initialized", params={}, raw={})
        )

        backend_names = self._transport.running_backends()
        self._tools_cache = await self._router.build(self._transport, backend_names)
        self._repo.save_routing_table(self._router.get_routing_table())

        self.discovery = ToolDiscovery(self._transport, backend_names, self._config)
        self._discovery_started = True
        await self._run_discovery()

        await self._notify_tools_changed()

        new_tools = self._router.get_all_tools().get(backend.name, [])
        summary: dict[str, Any] = {"backend": backend.name, "tool_count": len(new_tools), "tools": new_tools}
        if self.chain_tracker is not None:
            summary["labels"] = {name: self.chain_tracker.get_labels(name) for name in new_tools}
        return summary

    async def remove_backend_live(self, name: str) -> dict[str, Any]:
        """Stop a backend in the running proxy, rebuild routing/discovery
        over what remains, and notify connected clients."""
        assert self._transport is not None

        await self._transport.remove_backend(name)

        backend_names = self._transport.running_backends()
        self._tools_cache = await self._router.build(self._transport, backend_names)
        self._repo.save_routing_table(self._router.get_routing_table())

        self.discovery = ToolDiscovery(self._transport, backend_names, self._config)
        self._discovery_started = True
        await self._run_discovery()

        await self._notify_tools_changed()

        return {"removed": name, "remaining_backends": backend_names}

    async def _notify_tools_changed(self) -> None:
        notif = MCPMessage(method="notifications/tools/list_changed", params={}, raw={})
        if self._transport is not None:
            try:
                await self._transport.send_to_client(notif)
            except Exception:
                pass
        for send_fn in list(self._sse_clients.values()):
            try:
                await send_fn(notif)
            except Exception:
                pass

    async def _message_loop(self) -> None:
        assert self._transport is not None
        logger.debug("Message loop started. Routing table: %s", self._router.get_routing_table())

        while self._running:
            try:
                msg = await self._transport.receive_message()
                logger.debug("<<< client  method=%s id=%s params=%s", msg.method, msg.id, msg.params)
            except EOFError:
                logger.info("Client disconnected (EOF on stdin).")
                break
            except Exception as exc:
                logger.error("Failed to read client message: %s\n%s", exc, traceback.format_exc())
                continue

            try:
                await self._handle_message(msg)
                logger.debug(">>> handled method=%s id=%s", msg.method, msg.id)
            except Exception as exc:
                logger.error(
                    "Unhandled exception processing message: %s\n%s", exc, traceback.format_exc()
                )
                err = MCPMessage.make_error(msg.id, -32000, f"Internal proxy error: {exc}")
                await self._send_to_client(err)

    async def _handle_message(self, msg: MCPMessage) -> None:
        assert self._transport is not None

        # JSON-RPC response (no method) — forward to backend, no reply expected
        if msg.method is None:
            logger.debug("Forwarding JSON-RPC response id=%s to backends", msg.id)
            await self._handle_response(msg)
            return

        # Notification (no id) — fire-and-forget to all backends, no reply expected
        if msg.id is None:
            logger.debug("Forwarding notification method=%s to backends", msg.method)
            await self._handle_notification(msg)
            return

        if msg.method == "initialize":
            await self._handle_initialize(msg)
        elif msg.method == "tools/list":
            await self._handle_tools_list(msg)
        elif msg.method == "tools/call":
            await self._handle_tools_call(msg)
        else:
            await self._handle_fallback(msg)

    async def _handle_initialize(self, msg: MCPMessage) -> None:
        assert self._transport is not None

        session = self._session_manager.create_session()
        self._current_session = session
        logger.info("Session created: %s", session.session_id)
        self._repo.upsert_session(session.session_id, session.created_at.isoformat(), session.state.value, 0)

        backend_names = self._transport.running_backends()

        # Step 1: Initialize all backends (MCP protocol handshake)
        for backend_name in backend_names:
            await self._transport.send_to_backend(backend_name, msg)
            logger.debug("Backend '%s' initialized", backend_name)

        # Step 2: Send 'initialized' notification to all backends
        # MCP spec requires this before any tools/list or tools/call.
        initialized_notif = MCPMessage(
            method="notifications/initialized",
            params={},
            raw={},
        )
        for backend_name in backend_names:
            await self._transport.send_notification_to_backend(backend_name, initialized_notif)

        # Step 3: Respond to client ASAP — routing table will be built on first tools/list
        response = MCPMessage(
            id=msg.id,
            result={
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mcpsec", "version": "0.1.0"},
            },
            raw={},
        )
        await self._send_to_client(response)

    async def _handle_tools_list(self, msg: MCPMessage) -> None:
        import asyncio

        assert self._transport is not None

        if self._tools_cache is not None:
            # Return cached tools — don't go to backends again
            logger.info("tools/list returning %d cached tools", len(self._tools_cache))
        else:
            # First call: build routing table (which queries tools/list from all backends)
            backend_names = self._transport.running_backends()
            self._tools_cache = await self._router.build(self._transport, backend_names)
            logger.info("tools/list fetched %d tools from backends", len(self._tools_cache))
            self._repo.save_routing_table(self._router.get_routing_table())

        response = MCPMessage(
            id=msg.id,
            result={"tools": self._tools_cache},
            raw={},
        )
        await self._send_to_client(response)

        # Start discovery AFTER first tools/list completes — both initialize
        # and tools/list are done, so discovery won't block the client.
        if not self._discovery_started:
            self._discovery_started = True
            backend_names = self._transport.running_backends()
            self.discovery = ToolDiscovery(self._transport, backend_names, self._config)
            asyncio.create_task(self._run_discovery())

    async def _handle_tools_call(self, msg: MCPMessage) -> None:
        assert self._transport is not None

        tool_name: str = msg.params.get("name", "")
        if not tool_name:
            err = MCPMessage.make_error(msg.id, -32602, "Missing tool name in params.")
            await self._send_to_client(err)
            return

        # Resolve backend
        try:
            backend_name = self._router.resolve(tool_name)
            logger.debug("tool '%s' resolved to backend '%s'", tool_name, backend_name)
        except ToolNotFoundError as exc:
            logger.warning("BLOCKED tools/call: %s | routing table: %s", exc, self._router.get_routing_table())
            err = MCPMessage.make_error(msg.id, -32601, str(exc))
            await self._send_to_client(err)
            return

        # Ensure we have a session
        if self._current_session is None:
            self._current_session = self._session_manager.create_session()
            logger.info(
                "Auto-created session: %s", self._current_session.session_id
            )

        session = self._current_session
        tool_labels = self._tool_labels(tool_name)
        if self._config.state_machine.enabled:
            session.apply_request_context(tool_name, tool_labels)

        # Record request event
        request_event = SessionEvent(
            timestamp=datetime.now(tz=timezone.utc),
            direction="request",
            tool_name=tool_name,
            content=msg.params,
        )
        session.add_event(request_event)
        await _broadcast_event(session.session_id, request_event)

        # Request analysis — regex filter
        req_flags = analyze_request(tool_name, msg.params)
        req_result = decide(
            req_flags,
            self._config.enforcement.default_mode,
            rules_file=self._config.enforcement.rules_file,
            session_state=session.state.value,
        )
        req_result = apply_tainted_escalation(
            req_result,
            tool_labels=tool_labels,
            session_state=session.state.value,
        )
        request_event.flags = req_flags
        request_event.decision = req_result.decision

        if req_result.is_blocking:
            logger.warning("BLOCKED request: tool=%s flags=%s", tool_name, req_flags)
            self._repo.save_event(session.session_id, request_event.to_dict())
            self._repo.upsert_session(session.session_id, session.created_at.isoformat(), session.state.value, len(session.events))
            err = MCPMessage.make_error(msg.id, -32000, f"Blocked by MCPSec: {req_flags}")
            await self._send_to_client(err)
            return

        # Chain tracking — runs after regex filter
        if self.chain_tracker is not None:
            event_id = len(session.events)
            ct_result = self.chain_tracker.check(session, tool_name, event_id, backend_name)
            if ct_result.matched_combination:
                logger.warning(
                    "Chain tracking: combination=%s step=%s decision=%s tool=%s",
                    ct_result.matched_combination,
                    ct_result.step,
                    ct_result.decision,
                    tool_name,
                )
                request_event.flags = list(request_event.flags) + [
                    f"chain:{ct_result.matched_combination}:{ct_result.step}"
                ]
                if ct_result.decision in ("ALERT", "BLOCK"):
                    await _broadcast_chain_event(session.session_id, tool_name, ct_result)
            if ct_result.decision == "BLOCK":
                combo = ct_result.matched_combination or "unknown"
                step = ct_result.step or "?"
                err = MCPMessage.make_error(
                    msg.id,
                    -32600,
                    f"MCPSec: Tool call blocked — dangerous chain detected ({combo}, step {step}). "
                    f"Tool '{tool_name}' continues a {combo} chain.",
                )
                request_event.decision = "block"
                self._repo.save_event(session.session_id, request_event.to_dict())
                self._repo.upsert_session(session.session_id, session.created_at.isoformat(), session.state.value, len(session.events))
                await self._send_to_client(err)
                return

        # Anomaly detection — predefined + adaptive z-score, severity fused
        # with Toxic Flow risk: final = clip(base × multiplier)
        if self.anomaly_detector is not None:
            anomaly = self.anomaly_detector.check(tool_name)
            if anomaly.flags:
                # Per-flag rule overrides (rules.yaml) still apply; take the
                # more restrictive of rule decision and severity-based action.
                rule_result = decide(
                    anomaly.flags,
                    self._config.enforcement.default_mode,
                    rules_file=self._config.enforcement.rules_file,
                    session_state=session.state.value,
                )
                decision = more_restrictive(anomaly.action, rule_result.decision)
                logger.warning(
                    "Anomaly detected: flags=%s base=%s multiplier=%.1f final=%s decision=%s tool=%s",
                    anomaly.flags,
                    anomaly.base_severity,
                    anomaly.multiplier,
                    anomaly.final_severity,
                    decision,
                    tool_name,
                )
                request_event.flags = list(request_event.flags) + anomaly.flags + [
                    f"anomaly_severity:{anomaly.final_severity}"
                ]
                if decision == "block":
                    request_event.decision = "block"
                    self._repo.save_event(session.session_id, request_event.to_dict())
                    self._repo.upsert_session(session.session_id, session.created_at.isoformat(), session.state.value, len(session.events))
                    err = MCPMessage.make_error(
                        msg.id,
                        -32000,
                        f"Blocked by MCPSec: anomaly detected "
                        f"(severity={anomaly.final_severity}, flags={anomaly.flags})",
                    )
                    await self._send_to_client(err)
                    return

        self._repo.save_event(session.session_id, request_event.to_dict())
        self._repo.upsert_session(session.session_id, session.created_at.isoformat(), session.state.value, len(session.events))

        # Forward to backend
        response = await self._transport.send_to_backend(backend_name, msg)

        # Response analysis
        resp_content = response.result or response.error or {}
        resp_flags = analyze_response(tool_name, resp_content)
        resp_result = decide(
            resp_flags,
            self._config.enforcement.default_mode,
            rules_file=self._config.enforcement.rules_file,
            session_state=session.state.value,
        )

        # Redact credentials from response before forwarding to client
        if resp_result.redact:
            resp_content = redact_credentials(resp_content)
            if response.result is not None:
                response = MCPMessage(
                    id=response.id,
                    method=response.method,
                    result=resp_content,
                    error=response.error,
                    raw=response.raw,
                )
            logger.info("Redacted credentials in response: tool=%s", tool_name)

        if self._config.state_machine.enabled:
            session.apply_response_context(
                tool_name,
                tool_labels,
                resp_flags,
                resp_content,
                self._config.state_machine.sanitizer_tools,
            )

        if req_flags:
            logger.warning("REQUEST  flags=%s decision=%s tool=%s", req_flags, req_result.decision, tool_name)
        if resp_flags:
            logger.warning("RESPONSE flags=%s decision=%s redact=%s tool=%s", resp_flags, resp_result.decision, resp_result.redact, tool_name)

        response_event = SessionEvent(
            timestamp=datetime.now(tz=timezone.utc),
            direction="response",
            tool_name=tool_name,
            content=resp_content,
            flags=resp_flags,
            decision=resp_result.decision,
        )
        session.add_event(response_event)
        await _broadcast_event(session.session_id, response_event)
        self._repo.save_event(session.session_id, response_event.to_dict())
        self._repo.upsert_session(session.session_id, session.created_at.isoformat(), session.state.value, len(session.events))

        await self._send_to_client(response)

    def _tool_labels(self, tool_name: str) -> list[str]:
        if self.chain_tracker is None:
            return []
        return self.chain_tracker.get_labels(tool_name)

    async def _handle_notification(self, msg: MCPMessage) -> None:
        """Fire-and-forget: forward notification to all backends, no response expected."""
        assert self._transport is not None
        for backend_name in self._transport.running_backends():
            await self._transport.send_notification_to_backend(backend_name, msg)

    async def _handle_response(self, msg: MCPMessage) -> None:
        """Forward a JSON-RPC response (from client) back to the originating backend."""
        assert self._transport is not None
        # Best-effort: send to all backends — only the one that issued the request will care
        for backend_name in self._transport.running_backends():
            await self._transport.send_notification_to_backend(backend_name, msg)

    async def _handle_fallback(self, msg: MCPMessage) -> None:
        assert self._transport is not None

        backend_names = self._transport.running_backends()
        if not backend_names:
            err = MCPMessage.make_error(msg.id, -32000, "No backends available.")
            await self._send_to_client(err)
            return

        response = await self._transport.send_to_backend(backend_names[0], msg)
        await self._send_to_client(response)


async def _broadcast_event(session_id: str, event: SessionEvent) -> None:
    """Forward event to WebSocket broadcaster (imported lazily to avoid circular imports)."""
    try:
        from ..api.websocket import broadcast_event  # noqa: PLC0415
        await broadcast_event(session_id, event)
    except Exception:
        pass


async def _broadcast_chain_event(session_id: str, tool_name: str, ct_result: Any) -> None:
    """Broadcast chain tracking alert/block over WebSocket."""
    try:
        from ..api.websocket import broadcast_raw  # noqa: PLC0415
        event_type = (
            "chain_tracking_block" if ct_result.decision == "BLOCK" else "chain_tracking_alert"
        )
        await broadcast_raw({
            "type": event_type,
            "session_id": session_id,
            "decision": ct_result.decision,
            "matched_combination": ct_result.matched_combination,
            "step": ct_result.step,
            "tool": tool_name,
            "context": ct_result.context,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        })
    except Exception:
        pass
