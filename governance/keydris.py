"""Keydris: the authorization gateway that sits in front of every tool.

Architecture mirror
-------------------
In the real product, **Keydris middleware** wraps an MCP server and decides
whether a tool call may execute, based on the caller's declared governance
state. This module is a faithful, mock-but-production-shaped implementation of
that middleware:

    request  ->  keydris-reader reads GovernanceContext from request context
             ->  PolicyEngine evaluates the mathematical gate
             ->  ALLOW  : the tool body runs
                 DENY   : the tool body is never invoked; an APPROVAL REQUIRED
                          (or NO ACTION / DENIED) payload is returned instead

The gate is intentionally *fail-closed*: missing or malformed context is DENIED,
the exact 0.90 boundary is treated as "not proven malicious", and every
non-malicious-in-a-safe-band outcome requires a human.
"""

from __future__ import annotations

import functools
from contextvars import ContextVar, Token
from typing import Awaitable, Callable

from .config import DEFAULT_AUTO_BLOCK_MIN_CONFIDENCE, get_env
from .schemas import (
    GovernanceContext,
    GovernanceDecision,
    ThreatVerdict,
    ToolResponse,
)

# ---------------------------------------------------------------------------
# Request-scoped governance state ("keydris-reader")
# ---------------------------------------------------------------------------

_governance_context: ContextVar[GovernanceContext | None] = ContextVar(
    "keydris_governance_context", default=None
)


def bind_governance_context(ctx: GovernanceContext) -> Token:
    """Bind the caller's declared state to the current request/task context."""

    return _governance_context.set(ctx)


def reset_governance_context(token: Token) -> None:
    _governance_context.reset(token)


class KeydrisReader:
    """The 'keydris-reader' middleware component.

    Its only job is to read the agent's governance state out of the request
    context so the policy engine can evaluate it. It does not mutate anything.
    """

    def read(self) -> GovernanceContext | None:
        return _governance_context.get()


# ---------------------------------------------------------------------------
# Policy engine — the mathematical guardrail
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Deterministic authorization logic. No LLM, no I/O, no side effects.

    Rules
    -----
    1. ``malicious AND confidence > threshold``  -> ALLOWED (auto-block).
    2. ``benign AND confidence >= threshold``    -> NO_ACTION (no containment).
    3. everything else                           -> APPROVAL_REQUIRED.

    Rule 3 deliberately covers ``suspicious`` at any confidence, ``malicious``
    at or below the threshold, and the exact ``confidence == 0.90`` boundary.
    "Proven beyond threshold" is the only thing that auto-executes.
    """

    def __init__(self, auto_block_min_confidence: float | None = None) -> None:
        if auto_block_min_confidence is None:
            auto_block_min_confidence = float(
                get_env(
                    "KEYDRIS_AUTO_BLOCK_MIN_CONFIDENCE",
                    str(DEFAULT_AUTO_BLOCK_MIN_CONFIDENCE),
                )
            )
        self.auto_block_min_confidence = auto_block_min_confidence

    def evaluate(self, ctx: GovernanceContext | None) -> GovernanceDecision:
        if ctx is None:
            return GovernanceDecision.DENIED

        is_malicious = ctx.verdict == ThreatVerdict.MALICIOUS
        is_benign = ctx.verdict == ThreatVerdict.BENIGN

        # Rule 1 — the ONLY path to automatic execution.
        if is_malicious and ctx.confidence > self.auto_block_min_confidence:
            return GovernanceDecision.ALLOWED

        # Rule 2 — confidently benign, nothing to contain.
        if is_benign and ctx.confidence >= self.auto_block_min_confidence:
            return GovernanceDecision.NO_ACTION

        # Rule 3 — fail closed to a human.
        return GovernanceDecision.APPROVAL_REQUIRED

    def explain(self, ctx: GovernanceContext | None, decision: GovernanceDecision) -> str:
        """Human-readable audit string for the decision."""

        if ctx is None:
            return "DENIED: no governance context was present on the request."
        if decision == GovernanceDecision.ALLOWED:
            return (
                f"ALLOWED: verdict=malicious and confidence={ctx.confidence:.4f} "
                f"> {self.auto_block_min_confidence:.2f}; auto-block authorized."
            )
        if decision == GovernanceDecision.NO_ACTION:
            return (
                f"NO_ACTION: verdict=benign and confidence={ctx.confidence:.4f} "
                f">= {self.auto_block_min_confidence:.2f}; no containment needed."
            )
        return (
            f"APPROVAL_REQUIRED: verdict={ctx.verdict.value} "
            f"confidence={ctx.confidence:.4f} does not satisfy the auto-block rule "
            f"(malicious AND confidence > {self.auto_block_min_confidence:.2f})."
        )


# ---------------------------------------------------------------------------
# The middleware decorator
# ---------------------------------------------------------------------------

# A guarded tool returns the raw implementation dict on success; the wrapper
# normalizes it into a ToolResponse.
ToolImpl = Callable[..., Awaitable[dict]]


def keydris_guard(
    policy: PolicyEngine | None = None,
    reader: KeydrisReader | None = None,
) -> Callable[[ToolImpl], ToolImpl]:
    """Wrap an MCP tool body so it can only run when the policy engine allows it.

    The wrapped function's return value is always a serialized ``ToolResponse``
    (a plain dict) so it is valid MCP structured output either way.
    """

    policy = policy or PolicyEngine()
    reader = reader or KeydrisReader()

    def decorator(impl: ToolImpl) -> ToolImpl:
        @functools.wraps(impl)
        async def wrapper(*args, **kwargs) -> dict:
            ctx = reader.read()
            decision = policy.evaluate(ctx)
            explanation = policy.explain(ctx, decision)

            target = ctx.target if ctx else kwargs.get("ip") or (args[0] if args else None)

            if decision == GovernanceDecision.ALLOWED:
                # Authorized: the real containment side effect runs now.
                result = await impl(*args, **kwargs)
                return ToolResponse(
                    status=decision,
                    executed=True,
                    tool="block_ip",
                    target=target,
                    message=explanation,
                    payload=result,
                ).model_dump(mode="json")

            # Intercepted: the tool body is NEVER invoked.
            return ToolResponse(
                status=decision,
                executed=False,
                tool="block_ip",
                target=target,
                message=explanation,
                payload={
                    "requires_human_approval": decision
                    == GovernanceDecision.APPROVAL_REQUIRED,
                    "intercepted_by": "keydris",
                    "requested_action": ctx.action if ctx else None,
                    "evidence": {
                        "alert_id": ctx.alert_id if ctx else None,
                        "verdict": ctx.verdict.value if ctx else None,
                        "confidence": ctx.confidence if ctx else None,
                    },
                },
            ).model_dump(mode="json")

        return wrapper

    return decorator