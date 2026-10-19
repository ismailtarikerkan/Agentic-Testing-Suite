from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
from typing import Any
from urllib.parse import urljoin

import httpx

from ..config import BackendConfig
from .base import BaseTransport, MCPMessage

logger = logging.getLogger("proxy.stdio")

HTTP_CONNECT_TIMEOUT = 10.0
HTTP_RESPONSE_TIMEOUT = 30.0


class _HttpSseBackend:
    """One remote MCP backend reached over HTTP+SSE — the client-side
    mirror of mcpsec/proxy/sse_transport.py's server-side implementation:
    GET <url> opens an SSE stream whose first event gives the POST URL to
    send JSON-RPC messages to; responses arrive asynchronously back over
    that same SSE stream, matched to requests by `id`."""

    def __init__(self, url: str) -> None:
        self._url = url
        self._client: httpx.AsyncClient | None = None
        self._post_url: str | None = None
        self._pending: dict[Any, asyncio.Future] = {}
        self._listen_task: asyncio.Task | None = None
        self._ready = asyncio.Event()

    async def connect(self) -> None:
        self._client = httpx.AsyncClient(timeout=None)
        self._listen_task = asyncio.create_task(self._listen())
        await asyncio.wait_for(self._ready.wait(), timeout=HTTP_CONNECT_TIMEOUT)

    async def _listen(self) -> None:
        assert self._client is not None
        try:
            async with self._client.stream("GET", self._url, headers={"Accept": "text/event-stream"}) as resp:
                event_type: str | None = None
                async for line in resp.aiter_lines():
                    if line.startswith("event:"):
                        event_type = line[len("event:"):].strip()
                        continue
                    if not line.startswith("data:"):
                        continue
                    data = line[len("data:"):].strip()
                    if event_type == "endpoint":
                        self._post_url = urljoin(self._url, data)
                        self._ready.set()
                    else:
                        try:
                            msg = json.loads(data)
                        except json.JSONDecodeError:
                            continue
                        fut = self._pending.pop(msg.get("id"), None)
                        if fut is not None and not fut.done():
                            fut.set_result(msg)
                    event_type = None
        except Exception as exc:
            logger.warning("HTTP+SSE backend stream ended (%s): %s", self._url, exc)
        finally:
            # Unblock anything still waiting on a response that'll never arrive.
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(RuntimeError("SSE stream closed."))
            self._pending.clear()

    async def send(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._client is None or self._post_url is None:
            raise RuntimeError("HTTP backend not connected.")
        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()
        self._pending[payload.get("id")] = fut
        await self._client.post(self._post_url, json=payload)
        return await asyncio.wait_for(fut, timeout=HTTP_RESPONSE_TIMEOUT)

    async def send_notification(self, payload: dict[str, Any]) -> None:
        if self._client is None or self._post_url is None:
            return
        await self._client.post(self._post_url, json=payload)

    def is_alive(self) -> bool:
        return self._listen_task is not None and not self._listen_task.done()

    async def close(self) -> None:
        if self._listen_task is not None:
            self._listen_task.cancel()
        if self._client is not None:
            await self._client.aclose()


class StdioTransport(BaseTransport):
    def __init__(self, backends: list[BackendConfig]) -> None:
        self._backend_configs: dict[str, BackendConfig] = {b.name: b for b in backends}
        self._processes: dict[str, asyncio.subprocess.Process] = {}
        self._http_backends: dict[str, _HttpSseBackend] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def start(self) -> None:
        for backend in self._backend_configs.values():
            await self._spawn(backend)

    async def add_backend(self, backend: BackendConfig) -> bool:
        """Register and spawn a new backend after start() — for live/hot-add."""
        self._backend_configs[backend.name] = backend
        return await self._spawn(backend)

    async def _spawn(self, backend: BackendConfig) -> bool:
        if backend.transport == "http":
            return await self._connect_http(backend)
        if backend.command is None:
            logger.error("Backend '%s' has no command configured.", backend.name)
            return False
        try:
            proc = await asyncio.create_subprocess_exec(
                backend.command,
                *backend.args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            self._processes[backend.name] = proc
            if backend.name not in self._locks:
                self._locks[backend.name] = asyncio.Lock()
            logger.info("Backend '%s' spawned (pid=%s).", backend.name, proc.pid)
            # Log stderr in background so we can see why backends crash
            asyncio.create_task(self._drain_stderr(backend.name, proc))
            return True
        except Exception as exc:
            logger.error("Failed to spawn backend '%s': %s", backend.name, exc)
            return False

    async def _connect_http(self, backend: BackendConfig) -> bool:
        if not backend.url:
            logger.error("Backend '%s' has no url configured.", backend.name)
            return False
        conn = _HttpSseBackend(backend.url)
        try:
            await conn.connect()
        except Exception as exc:
            logger.error("Failed to connect HTTP backend '%s' (%s): %s", backend.name, backend.url, exc)
            return False
        self._http_backends[backend.name] = conn
        if backend.name not in self._locks:
            self._locks[backend.name] = asyncio.Lock()
        logger.info("Backend '%s' connected via HTTP+SSE (%s).", backend.name, backend.url)
        return True

    async def _drain_stderr(self, name: str, proc: asyncio.subprocess.Process) -> None:
        """Read and log stderr from a backend process."""
        assert proc.stderr is not None
        try:
            while True:
                line = await proc.stderr.readline()
                if not line:
                    break
                text = line.decode(errors="replace").rstrip()
                if text:
                    logger.warning("stderr[%s]: %s", name, text)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # BaseTransport implementation
    # ------------------------------------------------------------------

    async def receive_message(self) -> MCPMessage:
        loop = asyncio.get_event_loop()
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line or not line.strip():
            raise EOFError("Client closed stdin.")
        data: dict[str, Any] = json.loads(line.strip())
        return MCPMessage.from_dict(data)

    async def send_to_client(self, msg: MCPMessage) -> None:
        payload = json.dumps(msg.to_dict()) + "\n"
        sys.stdout.write(payload)
        sys.stdout.flush()

    async def send_to_backend(self, backend_name: str, msg: MCPMessage) -> MCPMessage:
        lock = self._locks.get(backend_name)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[backend_name] = lock

        async with lock:
            return await self._send_to_backend_unlocked(backend_name, msg)

    async def _send_to_backend_unlocked(self, backend_name: str, msg: MCPMessage) -> MCPMessage:
        http_conn = self._http_backends.get(backend_name)
        if http_conn is not None:
            try:
                data = await http_conn.send(msg.to_dict())
                return MCPMessage.from_dict(data)
            except Exception as exc:
                logger.error("Error communicating with HTTP backend '%s': %s", backend_name, exc)
                return MCPMessage.make_error(
                    msg.id, -32000, f"Backend '{backend_name}' (http) did not respond: {exc}"
                )

        proc = self._processes.get(backend_name)
        if proc is None or proc.returncode is not None:
            # Try to respawn
            logger.warning("Backend '%s' is not running; attempting respawn.", backend_name)
            cfg = self._backend_configs.get(backend_name)
            if cfg:
                ok = await self._spawn(cfg)
                proc = self._processes.get(backend_name) if ok else None
            if proc is None or proc.returncode is not None:
                return MCPMessage.make_error(
                    msg.id, -32000, f"Backend '{backend_name}' is not available."
                )

        payload = (json.dumps(msg.to_dict()) + "\n").encode()
        try:
            assert proc.stdin is not None
            assert proc.stdout is not None
            logger.debug(">>> backend[%s] %s", backend_name, payload.decode().strip())
            proc.stdin.write(payload)
            await proc.stdin.drain()

            # Loop until we get the response matching our request id.
            # Backends may send server-initiated requests/notifications first.
            while True:
                line = await proc.stdout.readline()
                logger.debug("<<< backend[%s] %s", backend_name, line.decode(errors="replace").strip() if line else "<empty>")
                if not line:
                    return MCPMessage.make_error(
                        msg.id, -32000, f"Backend '{backend_name}' closed connection."
                    )
                data: dict[str, Any] = json.loads(line.strip())
                incoming = MCPMessage.from_dict(data)

                # Server-initiated request (has method + id) — ack it inline so backend unblocks
                if incoming.method is not None and incoming.id is not None:
                    logger.debug(
                        "backend[%s] sent server request '%s' id=%s; acknowledging inline",
                        backend_name, incoming.method, incoming.id,
                    )
                    # Provide proper responses for known server-initiated requests
                    if incoming.method == "roots/list":
                        cfg = self._backend_configs.get(backend_name)
                        roots = []
                        if cfg:
                            for arg in cfg.args:
                                if arg.startswith("/"):
                                    roots.append({"uri": f"file://{arg}", "name": arg})
                        result = {"roots": roots}
                    else:
                        result = {}
                    ack = json.dumps({"jsonrpc": "2.0", "id": incoming.id, "result": result}) + "\n"
                    proc.stdin.write(ack.encode())
                    await proc.stdin.drain()
                    continue

                # Server-initiated notification (has method, no id) — discard
                if incoming.method is not None and incoming.id is None:
                    logger.debug("backend[%s] sent notification '%s'; discarding", backend_name, incoming.method)
                    continue

                # This is a response — return it (id match not strictly required, backends always respond in order)
                return incoming

        except json.JSONDecodeError as exc:
            logger.error("Backend '%s' returned malformed JSON: %s", backend_name, exc)
            return MCPMessage.make_error(
                msg.id, -32000, f"Backend '{backend_name}' returned malformed JSON."
            )
        except Exception as exc:
            logger.error("Error communicating with backend '%s': %s", backend_name, exc)
            if proc.returncode is None:
                proc.kill()
            self._processes.pop(backend_name, None)
            cfg = self._backend_configs.get(backend_name)
            if cfg:
                asyncio.create_task(self._spawn(cfg))
            return MCPMessage.make_error(
                msg.id, -32000, f"Backend '{backend_name}' died during tool call."
            )

    async def send_notification_to_backend(self, backend_name: str, msg: MCPMessage) -> None:
        """Send a message to a backend without waiting for a response (notifications/responses)."""
        http_conn = self._http_backends.get(backend_name)
        if http_conn is not None:
            try:
                await http_conn.send_notification(msg.to_dict())
            except Exception as exc:
                logger.warning("Failed to send notification to HTTP backend '%s': %s", backend_name, exc)
            return

        proc = self._processes.get(backend_name)
        if proc is None or proc.returncode is not None:
            return
        payload = (json.dumps(msg.to_dict()) + "\n").encode()
        try:
            assert proc.stdin is not None
            logger.debug(">>> backend[%s] (no-reply) %s", backend_name, payload.decode().strip())
            proc.stdin.write(payload)
            await proc.stdin.drain()
        except Exception as exc:
            logger.warning("Failed to send notification to backend '%s': %s", backend_name, exc)

    async def _terminate(self, name: str, proc: asyncio.subprocess.Process) -> None:
        logger.info("Terminating backend '%s' (pid=%s).", name, proc.pid)
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning("Backend '%s' did not exit; killing.", name)
            os.killpg(proc.pid, signal.SIGKILL)
            await proc.wait()
        except ProcessLookupError:
            pass

    async def remove_backend(self, name: str) -> bool:
        """Stop and forget a single backend — for live/hot-remove."""
        http_conn = self._http_backends.pop(name, None)
        if http_conn is not None:
            await http_conn.close()
        proc = self._processes.get(name)
        if proc is not None and proc.returncode is None:
            await self._terminate(name, proc)
        self._processes.pop(name, None)
        self._backend_configs.pop(name, None)
        self._locks.pop(name, None)
        return True

    async def close(self) -> None:
        for name, conn in list(self._http_backends.items()):
            await conn.close()
        self._http_backends.clear()
        for name, proc in list(self._processes.items()):
            if proc.returncode is not None:
                continue
            await self._terminate(name, proc)
        self._processes.clear()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def running_backends(self) -> list[str]:
        stdio_running = [
            name
            for name, proc in self._processes.items()
            if proc.returncode is None
        ]
        http_running = [
            name
            for name, conn in self._http_backends.items()
            if conn.is_alive()
        ]
        return stdio_running + http_running

    def all_backend_names(self) -> list[str]:
        return list(self._backend_configs.keys())
