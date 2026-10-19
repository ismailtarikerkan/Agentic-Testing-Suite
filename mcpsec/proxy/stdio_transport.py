from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
from typing import Any

from ..config import BackendConfig
from .base import BaseTransport, MCPMessage

logger = logging.getLogger("proxy.stdio")


class StdioTransport(BaseTransport):
    def __init__(self, backends: list[BackendConfig]) -> None:
        self._backend_configs: dict[str, BackendConfig] = {b.name: b for b in backends}
        self._processes: dict[str, asyncio.subprocess.Process] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def start(self) -> None:
        for backend in self._backend_configs.values():
            await self._spawn(backend)

    async def add_backend(self, backend: BackendConfig) -> bool:
        """Register and spawn a new backend after start() — for live/hot-add."""
        self._backend_configs[backend.name] = backend
        return await self._spawn(backend)

    async def _spawn(self, backend: BackendConfig) -> bool:
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
        proc = self._processes.get(name)
        if proc is not None and proc.returncode is None:
            await self._terminate(name, proc)
        self._processes.pop(name, None)
        self._backend_configs.pop(name, None)
        self._locks.pop(name, None)
        return True

    async def close(self) -> None:
        for name, proc in list(self._processes.items()):
            if proc.returncode is not None:
                continue
            await self._terminate(name, proc)
        self._processes.clear()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def running_backends(self) -> list[str]:
        return [
            name
            for name, proc in self._processes.items()
            if proc.returncode is None
        ]

    def all_backend_names(self) -> list[str]:
        return list(self._backend_configs.keys())
