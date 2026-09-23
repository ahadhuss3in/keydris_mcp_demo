"""MCP client used by the LangGraph Enforcer node.

Prefers a *real* MCP round-trip: it spawns ``mcp_server.py`` as a stdio
subprocess and calls ``block_ip`` through the MCP protocol. If that transport is
unavailable (e.g. a constrained CI sandbox), it falls back to importing the same
guarded function in-process. Both paths cross the identical Keydris middleware,
so the guardrail semantics are unchanged.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from governance.config import (
    DEFAULT_ENFORCER_TRANSPORT,
    get_env,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVER_SCRIPT = PROJECT_ROOT / "mcp_server.py"


class MCPEnforcerClient:
    """Calls the ``block_ip`` MCP tool, with an in-process fallback."""

    def __init__(
        self,
        *,
        transport: str = DEFAULT_ENFORCER_TRANSPORT,
        server_script: Path = SERVER_SCRIPT,
        python_executable: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.transport = transport
        self.server_script = server_script
        self.python_executable = python_executable or sys.executable
        self.timeout = timeout
        self.last_transport_used: str | None = None

    @classmethod
    def from_env(cls) -> "MCPEnforcerClient":
        transport = get_env("ENFORCER_TRANSPORT", DEFAULT_ENFORCER_TRANSPORT) or "stdio"
        return cls(transport=transport)

    # -- public API ---------------------------------------------------------

    async def call_block_ip(
        self,
        *,
        ip: str,
        reason: str,
        governance: dict[str, Any],
    ) -> dict[str, Any]:
        """Invoke ``block_ip`` over the configured transport.

        Always returns a dict shaped like ``ToolResponse``; never raises for a
        policy decision (approval/denial are normal, expected outcomes).
        """

        arguments = {"ip": ip, "reason": reason, "governance": governance}

        if self.transport == "stdio":
            try:
                result = await self._call_stdio("block_ip", arguments)
                self.last_transport_used = "stdio"
                return result
            except Exception as exc:  # noqa: BLE001 - degrade to in-process
                self.last_transport_used = f"inprocess (stdio failed: {exc.__class__.__name__})"

        return await self._call_in_process(arguments)

    # -- transports ---------------------------------------------------------

    async def _call_stdio(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        params = StdioServerParameters(
            command=self.python_executable,
            args=[str(self.server_script)],
            env=dict(os.environ),  # propagate OPENROUTER_* / KEYDRIS_* to the server
            cwd=str(PROJECT_ROOT),  # so the server can import the `governance` package
        )

        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.call_tool(tool, arguments)
                return self._extract_payload(result)

    async def _call_in_process(self, arguments: dict[str, Any]) -> dict[str, Any]:
        # Import here so the stdio path doesn't pay FastMCP import cost twice.
        from mcp_server import block_ip as block_ip_tool

        self.last_transport_used = "inprocess"
        result = await block_ip_tool(**arguments)
        return result

    # -- response normalization --------------------------------------------

    @staticmethod
    def _extract_payload(result: Any) -> dict[str, Any]:
        """Pull the dict payload out of an MCP CallToolResult.

        FastMCP may expose the dict as ``structuredContent`` (possibly wrapped as
        ``{"result": {...}}``) or as JSON in a text content block.
        """

        structured = getattr(result, "structuredContent", None)
        if isinstance(structured, dict):
            if set(structured.keys()) == {"result"} and isinstance(
                structured["result"], dict
            ):
                return structured["result"]
            return structured

        for item in getattr(result, "content", []) or []:
            text = getattr(item, "text", None)
            if text:
                try:
                    parsed = json.loads(text)
                except ValueError:
                    continue
                if isinstance(parsed, dict):
                    return parsed

        # FastMCP reported an error result with no usable body.
        raise RuntimeError(f"unexpected MCP tool result: {result!r}")