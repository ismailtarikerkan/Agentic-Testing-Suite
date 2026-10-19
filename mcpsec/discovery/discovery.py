from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from ..config import MCPSecConfig
from .tokenizer import tokenize
from .validator import Warning, validate_tool
from ..proxy.base import BaseTransport, MCPMessage

logger = logging.getLogger("discovery")

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "storage", "results")
RESULT_FILE = os.path.join(RESULTS_DIR, "discovery_result.json")

PROBE_NAMES = [
    "debug", "shell", "exec", "execute", "run", "eval",
    "admin", "root", "sudo", "system", "internal",
    "raw_query", "sql", "query", "test", "dev",
]

# To detect language errors from codebases, since programming languages can have different vulnerabilities.
FINGERPRINTS: dict[str, list[str]] = {
    "python": [
        "Traceback (most recent call last)",
        ".py\"",
        "AttributeError",
        "TypeError",
        "ValueError",
    ],
    "nodejs": [
        "at Object.",
        "at Module.",
        ".js:",
        "ReferenceError",
        "TypeError: Cannot",
    ],
    "go": [
        "goroutine ",
        "panic:",
        "runtime error:",
        ".go:",
    ],
    "java": [
        "java.lang.",
        "at com.",
        "NullPointerException",
        "Exception in thread",
    ],
}

STACK_TRACE_PATTERNS = [
    "Traceback (most recent call last)",
    "at Object.",
    "at Module.",
    "goroutine ",
    "panic:",
    "java.lang.",
    "Exception in thread",
    "stack trace",
    "stacktrace",
]

VALIDATION_ERROR_PATTERNS = [
    "invalid", "must be", "required", "expected", "type error",
    "validation", "schema", "not found", "missing", "bad request",
    "argument", "parameter",
]

PERMISSION_ERROR_PATTERNS = [
    "permission", "forbidden", "unauthorized", "access denied",
    "not allowed", "403", "401",
]

METHOD_NOT_FOUND_PATTERNS = [
    "method not found", "not found", "unknown method", "no such",
    "-32601",
]

GRADE_ORDER = ["A", "B", "C", "D", "F"]


def _grade_worse(a: str, b: str) -> bool:
    """Return True if grade a is worse than grade b."""
    ai = GRADE_ORDER.index(a) if a in GRADE_ORDER else -1
    bi = GRADE_ORDER.index(b) if b in GRADE_ORDER else -1
    return ai > bi


class ToolDiscovery:
    def __init__(
        self,
        transport: BaseTransport,
        backend_names: list[str],
        config: MCPSecConfig,
    ) -> None:
        self._transport = transport
        self._backend_names = backend_names
        self._config = config
        self._result: dict | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> dict:
        logger.info("Tool discovery starting...")
        result = await self._run_discovery()
        self._result = result
        return result

    async def rescan(self) -> dict:
        logger.info("Tool discovery: rescan triggered.")
        result = await self._run_discovery()
        self._result = result
        return result

    def get_result(self) -> dict | None:
        return self._result

    # ------------------------------------------------------------------
    # Core pipeline
    # ------------------------------------------------------------------

    async def _run_discovery(self) -> dict:
        disc_config = getattr(self._config, "discovery", None)

        backends_data: dict[str, Any] = {}
        all_warnings: list[dict] = []
        all_hidden_tools: list[dict] = []

        # Load previous result for change detection
        previous_result = self._load_previous_result()

        for backend_name in self._backend_names:
            logger.info("Discovering backend '%s'...", backend_name)
            try:
                backend_data, warnings, hidden_tools = await self._discover_backend(
                    backend_name, disc_config
                )
                backends_data[backend_name] = backend_data
                all_warnings.extend(warnings)
                all_hidden_tools.extend(hidden_tools)
            except Exception as exc:
                logger.error("Discovery failed for backend '%s': %s", backend_name, exc)

        # Change detection
        changes: list[dict] = []
        if previous_result and getattr(disc_config, "change_detection", True):
            changes = self._detect_changes(previous_result, {"backends": backends_data})
            for change in changes:
                self._persist_change(change)
                if change.get("severity") == "CRITICAL":
                    logger.warning(
                        "CRITICAL tool change detected: %s/%s — %s",
                        change.get("backend"),
                        change.get("tool"),
                        [f.get("field") for f in change.get("fields", [])],
                    )
                    await self._broadcast_change(change)

        result: dict[str, Any] = {
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "previous_scan_at": previous_result.get("generated_at") if previous_result else None,
            "backends": backends_data,
            "hidden_tools": all_hidden_tools,
            "warnings": all_warnings,
            "changes": changes,
        }

        self._write_result(result)
        self._log_summary(backends_data, all_warnings, all_hidden_tools, changes)
        return result

    async def _discover_backend(
        self,
        backend_name: str,
        disc_config: Any,
    ) -> tuple[dict, list[dict], list[dict]]:
        # Step 1: tools/list
        request = MCPMessage(id=1, method="tools/list", params={}, raw={})
        response = await self._transport.send_to_backend(backend_name, request)

        if response.error:
            raise RuntimeError(
                f"Backend '{backend_name}' tools/list error: {response.error}"
            )

        raw_tools: list[dict] = []
        if response.result:
            raw_tools = response.result.get("tools", [])

        tools_data: dict[str, Any] = {}
        all_warnings: list[Warning] = []
        all_error_messages: list[str] = []

        for raw_tool in raw_tools:
            tool_name = raw_tool.get("name", "")
            if not tool_name:
                continue

            tool_entry, tool_warnings, error_msgs = await self._process_tool(
                backend_name, tool_name, raw_tool, disc_config
            )
            tools_data[tool_name] = tool_entry
            all_warnings.extend(tool_warnings)
            all_error_messages.extend(error_msgs)

        # Tech fingerprinting
        tech_stack = {"language": "unknown", "confidence": "none"}
        if getattr(disc_config, "tech_fingerprinting", True):
            tech_stack = self._fingerprint_tech(all_error_messages)

        # Hidden tool detection
        hidden_tools: list[dict] = []
        if getattr(disc_config, "hidden_tool_detection", True):
            hidden_tools = await self._detect_hidden_tools(backend_name)
            for ht in hidden_tools:
                ht["backend"] = backend_name

        backend_data: dict[str, Any] = {
            "tool_count": len(tools_data),
            "tech_stack": tech_stack,
            "tools": tools_data,
        }

        warnings_dicts = [w.to_dict() for w in all_warnings]
        return backend_data, warnings_dicts, hidden_tools

    async def _process_tool(
        self,
        backend_name: str,
        tool_name: str,
        raw_schema: dict,
        disc_config: Any,
    ) -> tuple[dict, list[Warning], list[str]]:
        description = raw_schema.get("description", "")
        input_schema = raw_schema.get("inputSchema") or {}
        properties: dict = input_schema.get("properties", {}) or {}

        # Tokenize
        name_tokens = tokenize(tool_name)
        desc_tokens = tokenize(description)
        param_tokens: dict[str, list[str]] = {}
        for param_name, param_schema in properties.items():
            if not isinstance(param_schema, dict):
                continue
            param_desc = param_schema.get("description", "")
            combined = f"{param_name} {param_desc}"
            param_tokens[param_name] = tokenize(combined)

        # Validate
        warnings = validate_tool(tool_name, raw_schema, backend_name)

        # Build parameter info
        required_fields: list[str] = input_schema.get("required", []) or []
        parameters: dict[str, Any] = {}
        for param_name, param_schema in properties.items():
            if not isinstance(param_schema, dict):
                continue
            parameters[param_name] = {
                "type": param_schema.get("type", "unknown"),
                "description": param_schema.get("description", ""),
                "required": param_name in required_fields,
            }

        # Schema probing
        security_grade = "unknown"
        probe_findings: list[dict] = []
        error_messages: list[str] = []

        if getattr(disc_config, "schema_probing", True):
            security_grade, probe_findings, error_messages = await self._probe_tool(
                backend_name, tool_name, raw_schema
            )

        tool_entry: dict[str, Any] = {
            "name": tool_name,
            "description": description,
            "tokens": {
                "name": name_tokens,
                "description": desc_tokens,
                "parameters": param_tokens,
            },
            "parameters": parameters,
            "security_grade": security_grade,
            "probe_findings": probe_findings,
            "warnings": [w.type for w in warnings],
            "hidden": False,
            "raw_schema": raw_schema,
        }

        return tool_entry, warnings, error_messages

    # ------------------------------------------------------------------
    # DISC-03: Schema probing
    # ------------------------------------------------------------------

    _MUTATING_KEYWORDS = [
        "send", "create", "draft", "write", "delete", "remove",
        "update", "put", "post", "insert", "move", "copy",
        "rename", "publish", "submit", "upload", "append",
    ]

    async def _probe_tool(
        self,
        backend_name: str,
        tool_name: str,
        schema: dict,
    ) -> tuple[str, list[dict], list[str]]:
        if any(kw in tool_name.lower() for kw in self._MUTATING_KEYWORDS):
            logger.info("Skipping probe for '%s' (mutating tool).", tool_name)
            return ("skipped", [], [])

        input_schema = schema.get("inputSchema") or {}
        properties: dict = input_schema.get("properties", {}) or {}

        findings: list[dict] = []
        error_messages: list[str] = []

        if not properties:
            # Nothing to probe
            return ("unknown", [], [])

        disc_config = getattr(self._config, "discovery", None)
        timeout_ms = getattr(disc_config, "probing_timeout_ms", 5000)
        timeout_s = timeout_ms / 1000.0

        for param_name, param_schema in properties.items():
            param_type = param_schema.get("type", "string") if isinstance(param_schema, dict) else "string"
            is_path_like = any(kw in param_name.lower() for kw in ["path", "file", "dir", "folder"])

            test_inputs: list[tuple[str, Any]] = [
                ("empty_value", ""),
                ("wrong_type", 0 if param_type == "string" else "notanumber"),
                ("oversized_string", "A" * 1000),
                ("special_chars", "'; DROP TABLE--"),
            ]
            if is_path_like:
                test_inputs.append(("path_traversal", "../../../etc/passwd"))

            for test_name, test_value in test_inputs:
                request = MCPMessage(
                    id=99,
                    method="tools/call",
                    params={"name": tool_name, "arguments": {param_name: test_value}},
                    raw={},
                )
                try:
                    response = await asyncio.wait_for(
                        self._transport.send_to_backend(backend_name, request),
                        timeout=timeout_s,
                    )
                except asyncio.TimeoutError:
                    logger.debug(
                        "Probe timeout for %s/%s param=%s test=%s",
                        backend_name, tool_name, param_name, test_name,
                    )
                    continue
                except Exception as exc:
                    logger.debug("Probe error: %s", exc)
                    continue

                response_text = self._response_to_text(response)
                if response_text:
                    error_messages.append(response_text)

                finding_type = self._classify_probe_response(response, response_text)
                severity = None
                if finding_type == "stack_trace":
                    severity = "HIGH"
                elif finding_type == "accepts_bad_input":
                    severity = "CRITICAL"

                if finding_type not in ("validated", None):
                    findings.append({
                        "param": param_name,
                        "test": test_name,
                        "result": finding_type,
                        "severity": severity,
                    })

        grade = self._calculate_grade(findings)
        return (grade, findings, error_messages)

    def _response_to_text(self, response: MCPMessage) -> str:
        parts: list[str] = []
        if response.error:
            msg = response.error.get("message", "")
            if msg:
                parts.append(str(msg))
        if response.result:
            content = response.result.get("content", [])
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        # A probed tool that "accepts bad input" may echo back a
                        # non-string value (e.g. the wrong_type test's int) in a
                        # text field — coerce so probing itself never crashes on it.
                        parts.append(str(item.get("text", "")))
            elif isinstance(content, str):
                parts.append(content)
        return " ".join(parts)

    def _classify_probe_response(self, response: MCPMessage, response_text: str) -> str:
        text_lower = response_text.lower()

        # Stack trace
        for pattern in STACK_TRACE_PATTERNS:
            if pattern.lower() in text_lower:
                return "stack_trace"

        # In-band MCP error: result present but isError=true (MCP convention).
        # Treat this the same as a JSON-RPC error — do NOT count as accepts_bad_input.
        is_inband_error = (
            response.result is not None
            and response.result.get("isError") is True
        )

        # Genuine success with bad input: result present, no in-band error flag
        if response.error is None and response.result is not None and not is_inband_error:
            content = response.result.get("content", [])
            if content:
                return "accepts_bad_input"

        # Proper validation error (works for both JSON-RPC errors and in-band errors)
        for pattern in VALIDATION_ERROR_PATTERNS:
            if pattern in text_lower:
                return "validated"

        # Generic server error
        if response.error is not None or is_inband_error:
            return "unvalidated_crash"

        return "unvalidated_crash"

    def _calculate_grade(self, findings: list[dict]) -> str:
        if not findings:
            return "A"

        has_critical = any(f.get("severity") == "CRITICAL" for f in findings)
        has_stack_trace = any(f.get("result") == "stack_trace" for f in findings)

        if has_critical or (has_stack_trace and len([f for f in findings if f.get("result") == "stack_trace"]) >= 2):
            return "F"

        validated_count = sum(1 for f in findings if f.get("result") == "validated")
        total = len(findings)
        ratio = validated_count / total if total > 0 else 0

        if ratio >= 0.9:
            return "A"
        elif ratio >= 0.7:
            return "B"
        elif ratio >= 0.5:
            return "C"
        elif ratio >= 0.2:
            return "D"
        else:
            return "F"

    # ------------------------------------------------------------------
    # DISC-04: Hidden tool detection
    # ------------------------------------------------------------------

    async def _detect_hidden_tools(self, backend_name: str) -> list[dict]:
        found: list[dict] = []
        disc_config = getattr(self._config, "discovery", None)
        timeout_s = getattr(disc_config, "probing_timeout_ms", 5000) / 1000.0

        for probe_name in PROBE_NAMES:
            request = MCPMessage(
                id=98,
                method="tools/call",
                params={"name": probe_name, "arguments": {}},
                raw={},
            )
            try:
                response = await asyncio.wait_for(
                    self._transport.send_to_backend(backend_name, request),
                    timeout=timeout_s,
                )
            except asyncio.TimeoutError:
                continue
            except Exception:
                continue

            classification = self._classify_hidden_tool_response(response)
            if classification is None:
                continue

            severity, response_type = classification
            entry = {
                "name": probe_name,
                "severity": severity,
                "response_type": response_type,
            }
            found.append(entry)
            logger.warning(
                "Hidden tool detected on backend '%s': '%s' (severity=%s, type=%s)",
                backend_name, probe_name, severity, response_type,
            )

        return found

    def _classify_hidden_tool_response(self, response: MCPMessage) -> tuple[str, str] | None:
        text = self._response_to_text(response).lower()

        # Method not found → tool does not exist
        for pattern in METHOD_NOT_FOUND_PATTERNS:
            if pattern in text:
                return None

        if response.error is not None:
            error_msg = str(response.error.get("message", "")).lower()
            code = response.error.get("code")

            # -32601 is JSON-RPC "method not found"
            if code == -32601:
                return None
            for pattern in METHOD_NOT_FOUND_PATTERNS:
                if pattern in error_msg:
                    return None

            # Permission/auth error
            for pattern in PERMISSION_ERROR_PATTERNS:
                if pattern in error_msg:
                    return ("MEDIUM", "permission_error")

            # Parameter/argument error → tool exists but needs params
            for pattern in VALIDATION_ERROR_PATTERNS:
                if pattern in error_msg:
                    return ("HIGH", "parameter_error")

            # Other error → treat as parameter error (tool exists)
            return ("HIGH", "parameter_error")

        # Got an actual result → tool is functional
        if response.result is not None:
            return ("CRITICAL", "functional_response")

        return None

    # ------------------------------------------------------------------
    # DISC-05: Technology fingerprinting
    # ------------------------------------------------------------------

    def _fingerprint_tech(self, error_messages: list[str]) -> dict:
        if not error_messages:
            return {"language": "unknown", "confidence": "none"}

        combined = " ".join(error_messages)
        scores: dict[str, int] = {}

        for lang, patterns in FINGERPRINTS.items():
            score = sum(1 for p in patterns if p in combined)
            if score > 0:
                scores[lang] = score

        if not scores:
            return {"language": "unknown", "confidence": "none"}

        best_lang = max(scores, key=lambda k: scores[k])
        best_score = scores[best_lang]

        if best_score >= 3:
            confidence = "high"
        elif best_score == 2:
            confidence = "medium"
        else:
            confidence = "low"

        return {"language": best_lang, "confidence": confidence}

    # ------------------------------------------------------------------
    # DISC-06: Change detection
    # ------------------------------------------------------------------

    def _detect_changes(self, old_result: dict, new_result: dict) -> list[dict]:
        changes: list[dict] = []
        old_backends: dict = old_result.get("backends", {})
        new_backends: dict = new_result.get("backends", {})

        for backend_name, new_backend in new_backends.items():
            old_backend = old_backends.get(backend_name, {})
            old_tools: dict = old_backend.get("tools", {})
            new_tools: dict = new_backend.get("tools", {})

            # New tools
            for tool_name in new_tools:
                if tool_name not in old_tools:
                    changes.append({
                        "tool": tool_name,
                        "backend": backend_name,
                        "change_type": "new_tool",
                        "severity": "HIGH",
                        "fields": [],
                    })

            # Removed tools
            for tool_name in old_tools:
                if tool_name not in new_tools:
                    changes.append({
                        "tool": tool_name,
                        "backend": backend_name,
                        "change_type": "removed_tool",
                        "severity": "LOW",
                        "fields": [],
                    })

            # Modified tools
            for tool_name, new_tool in new_tools.items():
                if tool_name not in old_tools:
                    continue
                old_tool = old_tools[tool_name]
                fields: list[dict] = []

                # Description changed
                old_desc = old_tool.get("description", "")
                new_desc = new_tool.get("description", "")
                if old_desc != new_desc:
                    fields.append({
                        "field": "description",
                        "before": old_desc,
                        "after": new_desc,
                        "severity": "CRITICAL",
                    })

                # Parameter changes
                old_params: dict = old_tool.get("parameters", {})
                new_params: dict = new_tool.get("parameters", {})
                for p_name in new_params:
                    if p_name not in old_params:
                        fields.append({
                            "field": f"parameter.{p_name}",
                            "before": None,
                            "after": new_params[p_name],
                            "severity": "HIGH",
                        })
                    else:
                        old_type = old_params[p_name].get("type")
                        new_type = new_params[p_name].get("type")
                        if old_type != new_type:
                            fields.append({
                                "field": f"parameter.{p_name}.type",
                                "before": old_type,
                                "after": new_type,
                                "severity": "HIGH",
                            })
                for p_name in old_params:
                    if p_name not in new_params:
                        fields.append({
                            "field": f"parameter.{p_name}",
                            "before": old_params[p_name],
                            "after": None,
                            "severity": "MEDIUM",
                        })

                # Security grade worsened
                old_grade = old_tool.get("security_grade", "unknown")
                new_grade = new_tool.get("security_grade", "unknown")
                if (old_grade in GRADE_ORDER and new_grade in GRADE_ORDER
                        and _grade_worse(new_grade, old_grade)):
                    fields.append({
                        "field": "security_grade",
                        "before": old_grade,
                        "after": new_grade,
                        "severity": "HIGH",
                    })

                if fields:
                    # Overall severity = worst field severity
                    sev_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                    worst = max(
                        fields,
                        key=lambda f: sev_order.index(f.get("severity", "LOW"))
                        if f.get("severity") in sev_order else 0,
                    )
                    changes.append({
                        "tool": tool_name,
                        "backend": backend_name,
                        "change_type": "modified",
                        "severity": worst.get("severity", "LOW"),
                        "fields": fields,
                    })

        return changes

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load_previous_result(self) -> dict | None:
        try:
            if os.path.exists(RESULT_FILE):
                with open(RESULT_FILE, "r") as f:
                    return json.load(f)
        except Exception as exc:
            logger.debug("Could not load previous discovery result: %s", exc)
        return None

    def _write_result(self, result: dict) -> None:
        os.makedirs(RESULTS_DIR, exist_ok=True)
        with open(RESULT_FILE, "w") as f:
            json.dump(result, f, indent=2, default=str)
        logger.info("Discovery result written to %s", RESULT_FILE)

    def _log_summary(
        self,
        backends_data: dict,
        warnings: list[dict],
        hidden_tools: list[dict],
        changes: list[dict],
    ) -> None:
        for backend_name, data in backends_data.items():
            tools = data.get("tools", {})
            grade_counts: dict[str, int] = {}
            for tool in tools.values():
                g = tool.get("security_grade", "unknown")
                grade_counts[g] = grade_counts.get(g, 0) + 1
            tech = data.get("tech_stack", {})
            logger.info(
                "Backend '%s': %d tools | tech=%s(%s) | grades=%s",
                backend_name,
                data.get("tool_count", 0),
                tech.get("language", "unknown"),
                tech.get("confidence", "none"),
                grade_counts,
            )

        if warnings:
            logger.info("Discovery warnings: %d total", len(warnings))

        if hidden_tools:
            logger.warning("Hidden tools found: %d", len(hidden_tools))

        if changes:
            critical = [c for c in changes if c.get("severity") == "CRITICAL"]
            logger.warning(
                "Change detection: %d changes (%d CRITICAL)",
                len(changes),
                len(critical),
            )

    def _persist_change(self, change: dict) -> None:
        try:
            from ..storage.repository import EventRepository  # noqa: PLC0415

            EventRepository().save_tool_change(change)
        except Exception as exc:
            logger.error("Failed to persist tool change: %s", exc)

    async def _broadcast_change(self, change: dict) -> None:
        try:
            from ..api.websocket import broadcast_raw  # noqa: PLC0415

            payload = dict(change)
            payload["type"] = "tool_change"
            payload["timestamp"] = datetime.now(tz=timezone.utc).isoformat()
            await broadcast_raw(payload)
        except Exception as exc:
            logger.debug("Failed to broadcast tool change: %s", exc)
