"""Keydris-guarded MCP server — the Enforcer.

Exposes a single tool, ``block_ip``, but the *tool body* is wrapped by Keydris
authorization middleware. The MCP caller (the LangGraph enforcer node) must send
its governance state alongside the request; the keydris-reader lifts that into
request context and the policy engine decides whether the containment side
effect is allowed to happen.

Flow for a call:

    MCP client
      -> block_ip(ip, reason, governance)          # governance is the agent's claim
      -> GovernanceContext.model_validate(...)     # typed, untrusted until validated
      -> bind_governance_context(ctx)              # keydris-reader can now read it
      -> guarded_block_ip(ip, reason)              # <- Keydris middleware boundary
           |-- ALLOWED          -> _block_ip_impl runs, returns success payload
           |-- APPROVAL_REQUIRED-> impl never runs, returns approval payload
           |-- NO_ACTION / DENIED-> impl never runs
      -> reset_governance_context(token)

Run as a stdio MCP server:  ``python mcp_server.py``
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from fastmcp import FastMCP

from governance import config  # noqa: F401  (loads .env for the server process)
from governance.keydris import (
    PolicyEngine,
    bind_governance_context,
    keydris_guard,
    reset_governance_context,
)
from governance.schemas import GovernanceContext

MCP_SERVER_NAME = "keydris-enforcer"

mcp: FastMCP = FastMCP(
    MCP_SERVER_NAME,
    instructions=(
        "Keydris-authorized security enforcement. All containment tools are "
        "gated by policy: only a malicious verdict above the confidence "
        "threshold executes automatically; everything else requires approval."
    ),
)


# ---------------------------------------------------------------------------
# The raw containment side effect (mock)
# ---------------------------------------------------------------------------


async def _block_ip_impl(ip: str, reason: str) -> dict[str, Any]:
    """Apply the containment action.

    In production this would call the firewall/EDR API. Here it is a mock so the
    PoC has no external effect, but it is only ever reached through the guard.
    """

    # Simulate a small amount of work at the enforcement boundary.
    await asyncio.sleep(0)

    return {
        "action": "block_ip",
        "ip": ip,
        "reason": reason,
        "rule_id": f"fw-rule-{abs(hash(ip)) % 10_000_000:07d}",
        "enforcement_point": "edge-firewall",
        "blocked_at": datetime.now(timezone.utc).isoformat(),
        "result": "blocked",
    }


# Keydris middleware wraps the body. `guarded_block_ip` is the authorization-aware
# version of `_block_ip_impl`.
_guarded_block_ip = keydris_guard(PolicyEngine())(_block_ip_impl)


# ---------------------------------------------------------------------------
# The MCP tool
# ---------------------------------------------------------------------------


async def block_ip(ip: str, reason: str, governance: dict[str, Any]) -> dict[str, Any]:
    """Block a source IP, subject to Keydris authorization.

    Args:
        ip: The source IP address to block.
        reason: Human-readable justification.
        governance: The calling agent's typed governance state
            (``alert_id``, ``verdict``, ``confidence``, ...). The policy engine
            treats this as an untrusted claim and validates it before use.

    Returns:
        A ``ToolResponse`` dict. ``status`` is one of ALLOWED, APPROVAL_REQUIRED,
        NO_ACTION, or DENIED; ``executed`` is True only for ALLOWED.
    """

    # Parse the caller's claim into the typed contract. A malformed payload means
    # there is no trustworthy context, so we bind None and let the engine DENY.
    ctx: GovernanceContext | None
    try:
        ctx = GovernanceContext.model_validate({**governance, "target": governance.get("target", ip)})
    except Exception:  # noqa: BLE001 - any validation failure is a denial
        ctx = None

    token = bind_governance_context(ctx) if ctx is not None else None
    try:
        return await _guarded_block_ip(ip, reason)
    finally:
        if token is not None:
            reset_governance_context(token)


# Register with FastMCP. `mcp.tool()` returns the original function, so the
# importable `block_ip` remains directly callable for the in-process fallback.
mcp.tool()(block_ip)


if __name__ == "__main__":
    # FastMCP defaults to stdio transport, which is what clients/mcp_client.py spawns.
    mcp.run()